package afclient

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// actionPriorities mirrors the action ladder ArtefactFlow authorises with: a higher action on a resource covers a lower one, so a token carrying vulnerability:delete also satisfies vulnerability:write. It only has to rank the actions a scope check here can meet.
var actionPriorities = map[string]int{"read": 1, "write": 2, "delete": 3, "deploy": 5, "manage": 10}

// TokenGrants reports whether the access token carries scope, directly or through a higher action on the same resource. known is false when the token's claims cannot be read (it is not a JWT, or names no scopes): the caller then has no answer and should let the API decide, rather than refuse a call that might succeed.
//
// The claims are read, never verified. That is enough for the one use this has, failing early with a clear message before calls the API would refuse anyway; the API remains the only authority on what a token may do.
func TokenGrants(token, scope string) (granted, known bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return false, false
	}
	var claims struct {
		Scopes *[]string `json:"scopes"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Scopes == nil {
		return false, false
	}

	wantResource, wantAction, _ := strings.Cut(scope, ":")
	for _, held := range *claims.Scopes {
		if held == scope {
			return true, true
		}
		resource, action, ok := strings.Cut(held, ":")
		if !ok || resource != wantResource {
			continue
		}
		have, haveKnown := actionPriorities[action]
		want, wantKnown := actionPriorities[wantAction]
		if haveKnown && wantKnown && have >= want {
			return true, true
		}
	}
	return false, true
}
