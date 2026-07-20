package afclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testClientID     = "507f191e810c19729de860ed"
	testClientSecret = "afsa_pretend-this-is-a-real-secret"
)

func TestAuthenticate(t *testing.T) {
	var (
		gotMethod, gotPath, gotContentType, gotAuthHeader string
		gotBody                                           tokenRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotContentType, gotAuthHeader = r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &gotBody)
		w.Write([]byte(`{"access_token":"minted-jwt","expire_in":300,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	token, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret, WithHTTPClient(srv.Client()), WithRetry(1, 0, 0))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if token != "minted-jwt" {
		t.Errorf("token = %q", token)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/auth/token" {
		t.Errorf("path = %q", gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q — the endpoint accepts JSON only, not form encoding", gotContentType)
	}
	// The credentials go in the body; the token call itself carries no Authorization header.
	if gotAuthHeader != "" {
		t.Errorf("Authorization = %q, want none on the token call", gotAuthHeader)
	}
	if gotBody.ClientID != testClientID || gotBody.ClientSecret != testClientSecret {
		t.Errorf("body = %+v", gotBody)
	}
}

// The minted token has to be the one every subsequent call presents.
func TestAuthenticatedClientUsesMintedToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token":
			w.Write([]byte(`{"access_token":"minted-jwt","expire_in":300,"token_type":"Bearer"}`))
		default:
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":"6a49227d9e270d46c3526074","version":"1.4.2"}`))
		}
	}))
	defer srv.Close()

	token, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret, WithHTTPClient(srv.Client()), WithRetry(1, 0, 0))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	c, err := New(srv.URL, token, WithHTTPClient(srv.Client()), WithRetry(1, 0, 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := c.CreateVersion(context.Background(), testArtefactID, VersionInput{Version: "1.4.2"}); err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	if gotAuth != "Bearer minted-jwt" {
		t.Errorf("Authorization = %q, want the minted token", gotAuth)
	}
}

// 401 covers several distinct causes at this endpoint, and only the code tells them apart. Each has to produce advice the reader can act on.
func TestAuthenticateErrorsAreActionable(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantSub string
	}{
		{"bad credentials", "AUTH00001", "client credentials were rejected"},
		{"deactivated account", "SERVICEACCOUNT01455", "deactivated"},
		{"expired account", "SERVICEACCOUNT01456", "expiry date"},
		{"unrecognised code", "SOMETHINGELSE", "HTTP 401"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"code":"` + tc.code + `","message":"Invalid credentials","logid":"abc123"}`))
			}))
			defer srv.Close()

			_, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret, WithHTTPClient(srv.Client()), WithRetry(1, 0, 0))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

// The secret must never reach an error string. The client id may — it is not a secret, and naming it makes a misconfigured workflow diagnosable.
func TestAuthenticateNeverLeaksTheSecret(t *testing.T) {
	statuses := []int{http.StatusUnauthorized, http.StatusBadRequest, http.StatusInternalServerError}
	for _, status := range statuses {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			// A hostile or careless API echoing the request back must not turn into a leak either.
			raw, _ := io.ReadAll(r.Body)
			w.Write(raw)
		}))
		_, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret, WithHTTPClient(srv.Client()), WithRetry(1, 0, 0))
		srv.Close()
		if err == nil {
			t.Errorf("status %d: expected an error", status)
			continue
		}
		if strings.Contains(err.Error(), testClientSecret) {
			t.Errorf("status %d: error leaked the client secret: %v", status, err)
		}
	}
}

func TestAuthenticateEmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"expire_in":300,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	if _, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret, WithHTTPClient(srv.Client()), WithRetry(1, 0, 0)); err == nil {
		t.Fatal("expected an error when the response carries no access_token")
	}
}

// Minting a token has no side effect beyond the token itself, so a transient failure is safe to replay — and the body has to survive the replay.
func TestAuthenticateRetriesWithBodyIntact(t *testing.T) {
	var calls int
	var lastBody tokenRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &lastBody)
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{"access_token":"minted-jwt","expire_in":300}`))
	}))
	defer srv.Close()

	token, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret, WithHTTPClient(srv.Client()), WithRetry(3, time.Millisecond, 5*time.Millisecond))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if token != "minted-jwt" {
		t.Errorf("token = %q", token)
	}
	if calls != 3 {
		t.Errorf("server saw %d calls, want 3", calls)
	}
	if lastBody.ClientID != testClientID || lastBody.ClientSecret != testClientSecret {
		t.Errorf("the replayed request lost its body: %+v", lastBody)
	}
}

// Bad credentials will still be bad on the third attempt.
func TestAuthenticateDoesNotRetry401(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"code":"AUTH00001","message":"Invalid credentials"}`))
	}))
	defer srv.Close()

	if _, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret, WithHTTPClient(srv.Client()), WithRetry(3, time.Millisecond, 5*time.Millisecond)); err == nil {
		t.Fatal("expected an error")
	}
	if calls != 1 {
		t.Errorf("server saw %d calls, want 1", calls)
	}
}
