package server

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/46labs/auth0/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

var actionTemplateRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// resolveTemplate replaces ${path.dot.notation} tokens in tmpl against ctx.
// Returns (resolved, true) when every referenced path produced a non-empty
// string. Returns ("", false) if any reference is empty or missing so the
// caller can skip emitting the claim, mirroring the Auth0 Action pattern of
// `if (event.user.x) api.idToken.setCustomClaim(...)`.
func resolveTemplate(tmpl string, ctx map[string]any) (string, bool) {
	if !strings.Contains(tmpl, "${") {
		// Literal — never skip.
		return tmpl, true
	}
	ok := true
	result := actionTemplateRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		path := match[2 : len(match)-1]
		v := lookupPath(ctx, path)
		if v == "" {
			ok = false
			return ""
		}
		return v
	})
	if !ok {
		return "", false
	}
	return result, true
}

// lookupPath walks ctx by dotted path, returning the value stringified.
// Returns "" when the path is unresolvable or terminates at a nil value.
func lookupPath(ctx map[string]any, path string) string {
	parts := strings.Split(path, ".")
	var cur any = ctx
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[p]
		if !ok {
			return ""
		}
	}
	if cur == nil {
		return ""
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", cur)
}

// buildPostLoginContext assembles the data context exposed to post_login
// templates. Mirrors Auth0's `event` object shape at a high level: user,
// authorization (org-scoped role), and client.
func (s *Server) buildPostLoginContext(user *config.User, client *config.Client) map[string]any {
	userMeta := map[string]any{}
	for k, v := range user.UserMetadata {
		userMeta[k] = v
	}

	ctx := map[string]any{
		"user": map[string]any{
			"user_id":      user.ID,
			"email":        user.Email,
			"phone_number": user.Phone,
			"name":         user.Name,
			"app_metadata": map[string]any{
				"tenant_id": user.AppMetadata.TenantID,
				"role":      user.AppMetadata.Role,
			},
			"user_metadata": userMeta,
		},
	}

	auth := map[string]any{}
	if user.AppMetadata.TenantID != "" {
		s.mu.RLock()
		members := s.members[user.AppMetadata.TenantID]
		s.mu.RUnlock()
		for _, m := range members {
			if m.UserID == user.ID {
				auth["role"] = m.Role
				auth["org_id"] = m.OrgID
				break
			}
		}
	}
	ctx["authorization"] = auth

	if client != nil {
		ctx["client"] = map[string]any{
			"client_id": client.ClientID,
			"name":      client.Name,
		}
	} else {
		ctx["client"] = map[string]any{}
	}

	return ctx
}

// applyPostLogin merges configured post_login claims into idClaims and
// accessClaims. Namespaced claims are prefixed with the issuer; raw claims
// land at the top level. Templates resolving to an empty value are dropped.
func (s *Server) applyPostLogin(user *config.User, client *config.Client, idClaims, accessClaims jwt.MapClaims) {
	pl := s.cfg.Actions.PostLogin
	if pl == nil {
		return
	}

	ctx := s.buildPostLoginContext(user, client)
	ns := strings.TrimSuffix(s.cfg.Issuer, "/") + "/"

	merge := func(claims jwt.MapClaims, src map[string]string, namespaced bool) {
		for name, tmpl := range src {
			value, ok := resolveTemplate(tmpl, ctx)
			if !ok {
				continue
			}
			key := name
			if namespaced {
				key = ns + name
			}
			claims[key] = value
		}
	}

	merge(idClaims, pl.IDTokenClaims, true)
	merge(idClaims, pl.IDTokenRawClaims, false)
	merge(accessClaims, pl.AccessTokenClaims, true)
	merge(accessClaims, pl.AccessTokenRawClaims, false)
}

// lookupClient returns the configured client by ID, or nil if unknown. Used
// to populate the post_login client context without panicking on unknown
// client_ids (the auth_code flow tolerates unknown clients today).
func (s *Server) lookupClient(clientID string) *config.Client {
	if clientID == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[clientID]; ok {
		return c
	}
	return nil
}
