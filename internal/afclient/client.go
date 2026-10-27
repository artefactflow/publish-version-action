// Package afclient is a small typed client for the ArtefactFlow API, scoped to the endpoints this action needs: resolving an artefact name to its id, creating a version, and replacing a version's recorded vulnerabilities.
//
// Authentication is centralised in a single bearer-token RoundTripper, so the token is applied in exactly one place and never reaches an error string or a log line. The base URL is always supplied by the caller (never hard-coded) per the ArtefactFlow integration rules.
package afclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one ArtefactFlow API instance.
type Client struct {
	baseURL string
	http    *http.Client
	retry   retryPolicy
	// token is held only so it can be scrubbed from a response body before that body becomes an error. It is never read for any other purpose: the bearer transport owns applying it.
	token string
}

// retryPolicy bounds how the client rides out transient upstream failures. Only failures a retry could plausibly fix are retried: connection errors, HTTP 429, and 5xx. Permanent failures (4xx other than 429) never retry. An exhausted retry still fails loudly: a workflow that could not register what it built must stop rather than report success.
type retryPolicy struct {
	maxAttempts int           // total tries including the first; <1 is clamped to 1
	baseDelay   time.Duration // backoff before the 2nd attempt; doubles each round
	maxDelay    time.Duration // ceiling on any single backoff sleep
}

func defaultRetry() retryPolicy {
	return retryPolicy{maxAttempts: 3, baseDelay: 200 * time.Millisecond, maxDelay: 5 * time.Second}
}

// delay computes the backoff before the retry following attempt index (0-based: 0 is the wait before the 2nd attempt). A server-supplied Retry-After wins, capped at maxDelay so one slow API cannot stall a whole job. Otherwise it is exponential with full jitter in [d/2, d], so a fleet of concurrent workflow runs does not synchronise its retry storm against a recovering API.
func (p retryPolicy) delay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, p.maxDelay)
	}
	if p.baseDelay <= 0 {
		return 0
	}
	d := p.baseDelay
	for i := 0; i < attempt && d < p.maxDelay; i++ {
		d *= 2
	}
	if d > p.maxDelay {
		d = p.maxDelay
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// UserAgent identifies the tool and its version on every request, including the token exchange, so ArtefactFlow can tell which release a service account runs: that is how users of a vulnerable release are found and told. main sets it from the build version.
var UserAgent = "publish-version-action/dev"

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying HTTP client. The bearer transport is layered on top of the provided client's transport.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithRetry overrides the bounded-retry policy for transient upstream failures. maxAttempts is the total number of tries including the first; a value below 1 is clamped to 1, which disables retries. baseDelay is the backoff before the second attempt and doubles each round up to maxDelay.
func WithRetry(maxAttempts int, baseDelay, maxDelay time.Duration) Option {
	return func(c *Client) {
		if maxAttempts < 1 {
			maxAttempts = 1
		}
		c.retry = retryPolicy{maxAttempts: maxAttempts, baseDelay: baseDelay, maxDelay: maxDelay}
	}
}

// New builds a Client for baseURL that authenticates every request with token. token must not be empty. It is never logged and is redacted from errors.
func New(baseURL, token string, opts ...Option) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("afclient: bearer token is required")
	}
	c, err := newClient(baseURL, opts...)
	if err != nil {
		return nil, err
	}
	base := c.http.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.token = token
	c.http.Transport = &bearerTransport{token: token, base: base}
	return c, nil
}

// newClient builds an unauthenticated client. Only the token endpoint uses one directly. Every other call goes through New and carries a bearer token.
func newClient(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("afclient: base URL is required")
	}
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 60 * time.Second},
		retry:   defaultRetry(),
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// bearerTransport injects the Authorization header on every request. Keeping it as a RoundTripper means auth is defined once, and the token lives nowhere else in the call path.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone before mutating: RoundTrippers must not modify the caller's request.
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}

// result is one successful response. The header is carried because the create call reads Location from it; every other caller ignores it.
type result struct {
	status int
	body   []byte
	header http.Header
}

// getJSON performs a GET against path (relative to the base URL) and decodes a 200 body into dst. Non-200 responses become errors that name the status and whatever the API said, never the token.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, dst any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	res, err := c.do(ctx, http.MethodGet, u, nil, http.StatusOK)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(res.body, dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// sendJSON performs a request carrying a JSON body and returns the response for any of the accepted statuses.
func (c *Client) sendJSON(ctx context.Context, method, path string, payload any, okStatus ...int) (*result, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode %s %s body: %w", method, path, err)
	}
	return c.do(ctx, method, c.baseURL+path, body, okStatus...)
}

// doRaw performs a request and returns the raw body of an accepted response. It is the entry point for the token exchange, which needs no response headers.
func (c *Client) doRaw(ctx context.Context, method, fullURL string, reqBody []byte) ([]byte, error) {
	res, err := c.do(ctx, method, fullURL, reqBody, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return res.body, nil
}

// do performs a request, mapping any status outside okStatus to a descriptive error. Transient failures (connection errors, HTTP 429, and 5xx) are retried with exponential backoff and jitter, bounded by the client's retry policy; permanent failures (4xx other than 429) return immediately.
//
// reqBody is held as bytes rather than a reader so each attempt can build a fresh request. Every call that reaches here is safe to replay: the GETs are idempotent, replaying the token exchange only mints another short-lived token, the vulnerability upload is a full replace, and a create whose response was lost surfaces on replay as a 409 that the caller already knows how to interpret.
func (c *Client) do(ctx context.Context, method, fullURL string, reqBody []byte, okStatus ...int) (*result, error) {
	var (
		lastErr        error
		lastRetryAfter time.Duration
	)
	for attempt := 0; attempt < c.retry.maxAttempts; attempt++ {
		if attempt > 0 {
			if err := waitBackoff(ctx, c.retry.delay(attempt-1, lastRetryAfter)); err != nil {
				return nil, err
			}
		}
		res, retryable, retryAfter, err := c.doOnce(ctx, method, fullURL, reqBody, okStatus)
		if err == nil {
			return res, nil
		}
		// Record that an earlier attempt already went out. A write that succeeded server-side but whose response was lost is indistinguishable from one that never landed, and the only evidence the caller gets is that this response followed a retry.
		var se *StatusError
		if attempt > 0 && errors.As(err, &se) {
			se.AfterRetry = true
		}
		lastErr, lastRetryAfter = err, retryAfter
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

// doOnce performs a single attempt. It reports whether the failure is worth retrying and any server-requested Retry-After delay.
func (c *Client) doOnce(ctx context.Context, method, fullURL string, reqBody []byte, okStatus []int) (res *result, retryable bool, retryAfter time.Duration, err error) {
	var payload io.Reader
	if reqBody != nil {
		payload = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, payload)
	if err != nil {
		return nil, false, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// A cancelled or timed-out context is deliberate: never retry it.
		if ctx.Err() != nil {
			return nil, false, 0, err
		}
		// Connection refused/reset, DNS failure and the like are transient, and worth a retry.
		return nil, true, 0, err
	}
	defer resp.Body.Close()
	// The bodies here are a version document or a stored vulnerability list; a few megabytes is already far more than any legitimate response.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	for _, ok := range okStatus {
		if resp.StatusCode == ok {
			return &result{status: resp.StatusCode, body: body, header: resp.Header}, false, 0, nil
		}
	}
	// An error body is the one thing that reaches a log annotation, and an API (or a proxy in front of it) can quote the request back, headers included. Scrub the token before it can travel any further.
	statusErr := newStatusError(resp.StatusCode, scrub(body, c.token))
	if isRetryableStatus(resp.StatusCode) {
		return nil, true, parseRetryAfter(resp.Header.Get("Retry-After")), statusErr
	}
	return nil, false, 0, statusErr
}

// isRetryableStatus reports whether an HTTP status is a transient upstream failure worth retrying: rate limiting (429) or any server-side 5xx.
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// parseRetryAfter reads the delta-seconds form of a Retry-After header. The HTTP-date form is ignored (returns 0), falling back to normal backoff.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// waitBackoff sleeps for d, returning early with the context error if ctx is cancelled first so a retry loop never outlives its deadline.
func waitBackoff(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// StatusError is an unexpected response from the ArtefactFlow API.
type StatusError struct {
	Status int
	// Code, Message, and LogID are the API's own error envelope, when the body carried one. LogID is what support needs to find the request in the API's logs, so it is always surfaced.
	Code    string
	Message string
	LogID   string
	// Snippet is a bounded excerpt of the raw body, used when the response was not the documented error envelope: an HTML error page from a proxy, say.
	Snippet string
	// AfterRetry records that this response arrived on a retry rather than on the first attempt. It matters for exactly one case: a create that reports a conflict only after an earlier attempt failed transiently is far more likely to be the earlier attempt's own write landing than a genuine duplicate.
	AfterRetry bool
}

// Error codes the action can say something more useful about than the API's own wording. Anything else falls through to the generic message plus whatever the API said.
const (
	codeInvalidCredentials     = "AUTH00001"
	codeServiceAccountUnusable = "SERVICEACCOUNT01455"
	codeServiceAccountExpired  = "SERVICEACCOUNT01456"
)

// apiError is the API's error envelope. The log id field is `logid` on the wire.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	LogID   string `json:"logid"`
}

// newStatusError builds a StatusError, preferring the API's structured error body over a raw excerpt. A body that is not the documented envelope (a proxy's HTML error page, for instance) falls back to the excerpt.
func newStatusError(status int, body []byte) *StatusError {
	e := &StatusError{Status: status}
	var parsed apiError
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Code != "" {
		e.Code, e.Message, e.LogID = parsed.Code, parsed.Message, parsed.LogID
		return e
	}
	e.Snippet = snippet(body)
	return e
}

// detail renders whatever the API said about the failure, in one line.
func (e *StatusError) detail() string {
	parts := make([]string, 0, 3)
	if e.Message != "" {
		parts = append(parts, e.Message)
	}
	if e.Code != "" {
		parts = append(parts, "code "+e.Code)
	}
	if e.LogID != "" {
		parts = append(parts, "log id "+e.LogID)
	}
	if len(parts) == 0 {
		return e.Snippet
	}
	return strings.Join(parts, ", ")
}

func (e *StatusError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		// The token endpoint returns 401 for several distinct causes, and the codes are the only way to tell them apart: "invalid credentials" is deliberately returned for both an unknown client id and a wrong secret, so that one cannot be narrowed further.
		switch e.Code {
		case codeInvalidCredentials:
			return fmt.Sprintf("HTTP 401: the client credentials were rejected. Check `client-id` and `client-secret`; a rotated secret invalidates the previous one immediately (%s)", e.detail())
		case codeServiceAccountUnusable:
			return fmt.Sprintf("HTTP 401: the service account cannot mint tokens: it is deactivated, or its organisation is inactive (%s)", e.detail())
		case codeServiceAccountExpired:
			return fmt.Sprintf("HTTP 401: the service account has passed its expiry date and can no longer mint tokens. Extend it before it lapses (%s)", e.detail())
		}
		return fmt.Sprintf("HTTP 401: the token was rejected. Check that it is valid and not expired (%s)", e.detail())
	case http.StatusPaymentRequired:
		return fmt.Sprintf("HTTP 402: the organisation is over its plan limit, so no new version can be created. This is a billing limit rather than a workflow problem, and no retry or input change resolves it (%s)", e.detail())
	case http.StatusForbidden:
		// Both authorization axes fail with 403, and the scope is the one people check first. Name the team layer explicitly so a correctly-scoped service account is not mistaken for a scope problem. The calls need different scopes, so all three are named. The vulnerability upload is a version write; only the apply-vex-only PATCH needs vulnerability:write, which ArtefactFlow does not grant to service accounts.
		return fmt.Sprintf("HTTP 403: the service account needs the artefact:read scope to look an artefact up by name and version:write to create the version and upload its vulnerabilities; apply-vex-only needs vulnerability:write, which a service account cannot be granted. Its principal must also belong to a team with write access to the artefact's group (%s)", e.detail())
	case http.StatusNotFound:
		// Deliberately does not name what was missing. Three different calls can 404 (resolving the artefact, and both writes when the version is gone), and each caller wraps this with which one it was.
		return fmt.Sprintf("HTTP 404: not found on this instance (%s)", e.detail())
	case http.StatusConflict:
		return fmt.Sprintf("HTTP 409: that version already exists on this artefact (%s)", e.detail())
	default:
		return fmt.Sprintf("artefactflow api returned HTTP %d (%s)", e.Status, e.detail())
	}
}

// scrub removes every occurrence of secret from a response body before it becomes an error. Very short values are left alone: they are not real credentials, and replacing them would corrupt unrelated text.
func scrub(body []byte, secret string) []byte {
	if len(secret) < 8 || !bytes.Contains(body, []byte(secret)) {
		return body
	}
	return bytes.ReplaceAll(body, []byte(secret), []byte("«redacted»"))
}

func snippet(b []byte) string {
	const max = 512
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
