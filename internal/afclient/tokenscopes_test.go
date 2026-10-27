package afclient

import (
	"encoding/base64"
	"testing"
)

func jwtWithClaims(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(claims)) + ".sig"
}

func TestTokenGrants(t *testing.T) {
	cases := []struct {
		name          string
		token         string
		scope         string
		granted, know bool
	}{
		{"held directly", jwtWithClaims(`{"scopes":["artefact:read","vulnerability:write"]}`), "vulnerability:write", true, true},
		{"covered by a higher action", jwtWithClaims(`{"scopes":["vulnerability:manage"]}`), "vulnerability:write", true, true},
		// The case a service account always is: it can hold version:write but not vulnerability:write.
		{"a service account's token", jwtWithClaims(`{"scopes":["artefact:read","version:write"]}`), "vulnerability:write", false, true},
		{"a lower action does not cover a higher one", jwtWithClaims(`{"scopes":["vulnerability:read"]}`), "vulnerability:write", false, true},
		{"an empty scope list is an answer", jwtWithClaims(`{"scopes":[]}`), "vulnerability:write", false, true},
		{"no scopes claim is no answer", jwtWithClaims(`{"sub":"sa"}`), "vulnerability:write", false, false},
		{"not a JWT is no answer", "opaque-token", "vulnerability:write", false, false},
		{"an unreadable payload is no answer", "a.%%%.c", "vulnerability:write", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			granted, known := TokenGrants(tc.token, tc.scope)
			if granted != tc.granted || known != tc.know {
				t.Errorf("TokenGrants = (%v, %v), want (%v, %v)", granted, known, tc.granted, tc.know)
			}
		})
	}
}
