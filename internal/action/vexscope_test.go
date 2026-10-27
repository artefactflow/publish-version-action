package action

import (
	"encoding/base64"
	"strings"
	"testing"
)

func tokenWithScopes(scopes string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"scopes":`+scopes+`}`)) + ".sig"
}

// A service account can never hold vulnerability:write, so apply-vex-only has to stop before its first call, and the error has to point at the path that works.
func TestCheckVEXScopeStopsApplyVEXOnlyWithoutTheScope(t *testing.T) {
	err := CheckVEXScope(Config{ApplyVEXOnly: true}, tokenWithScopes(`["artefact:read","version:write"]`))
	if err == nil {
		t.Fatal("CheckVEXScope let apply-vex-only run with a token lacking vulnerability:write")
	}
	for _, want := range []string{"vulnerability:write", "vex-file", "analysis", "version:write"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

func TestCheckVEXScopeAllowsWhatItCannotRuleOut(t *testing.T) {
	cases := []struct {
		name  string
		cfg   Config
		token string
	}{
		{"not the apply-vex-only path", Config{}, tokenWithScopes(`["version:write"]`)},
		{"the token carries the scope", Config{ApplyVEXOnly: true}, tokenWithScopes(`["vulnerability:write"]`)},
		// The API stays the authority: a token the action cannot read is not refused on a guess.
		{"the token's scopes cannot be read", Config{ApplyVEXOnly: true}, "opaque-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckVEXScope(tc.cfg, tc.token); err != nil {
				t.Errorf("CheckVEXScope = %v, want nil", err)
			}
		})
	}
}
