package afclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// tokenRequest is the client-credentials body. grant_type is accepted but ignored by the API — the client-credentials grant is assumed — so it is not sent.
type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// tokenResponse is the minted access token. The expiry field is `expire_in` on the wire, and it is a count of seconds rather than a timestamp.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpireIn    int    `json:"expire_in"`
	TokenType   string `json:"token_type"`
}

// Authenticate exchanges service-account client credentials for a short-lived access token, which is the same bearer token the rest of the API expects.
//
// The token endpoint lives on the same origin as everything else, so baseURL is the one the caller already has. The credentials appear only in the request body: they are never logged, and the error paths below deliberately quote the API's own message rather than anything derived from the request.
//
// The token is used immediately and never stored, so its lifetime does not matter here. It is deliberately short — treat it as single-use rather than caching it.
func Authenticate(ctx context.Context, baseURL, clientID, clientSecret string, opts ...Option) (string, error) {
	c, err := newClient(baseURL, opts...)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(tokenRequest{ClientID: clientID, ClientSecret: clientSecret})
	if err != nil {
		return "", fmt.Errorf("authenticate: %w", err)
	}

	body, err := c.doRaw(ctx, http.MethodPost, c.baseURL+"/v1/auth/token", payload)
	if err != nil {
		// This is the one call that puts a secret on the wire, and a failed response can quote the request back — a validation error listing the offending field, or a proxy echoing the body. Scrub before the error can reach an annotation.
		return "", fmt.Errorf("authenticate service account %s: %w", clientID, redact(err, clientSecret))
	}

	var resp tokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("authenticate service account %s: decode token response: %w", clientID, err)
	}
	if resp.AccessToken == "" {
		return "", fmt.Errorf("authenticate service account %s: response contained no access_token", clientID)
	}
	return resp.AccessToken, nil
}

// redact replaces every occurrence of secret in err's message with a placeholder. The typed error is flattened in the process, which no caller depends on — an unreadable error is a smaller problem than a leaked credential.
//
// Very short values are left alone: they are not real secrets (the API requires at least 8 characters), and replacing them would corrupt unrelated text.
func redact(err error, secret string) error {
	if err == nil || len(secret) < 8 {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(msg, secret, "«client-secret redacted»"))
}
