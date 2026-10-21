package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/dop251/goja"
	"github.com/golang-jwt/jwt/v5"
)

// exchangeOutcome is what a custom-token-exchange Action decided.
type exchangeOutcome struct {
	userID   string
	org      string
	actor    map[string]any
	metadata map[string]any
	// code and reason are set when the Action refused the exchange.
	code, reason string
}

// profileAction is the deployed Action of the profile routing subjectType, or
// nil when no profile claims it.
func (s *Server) profileAction(subjectType string) *Action {
	s.teps.mu.RLock()
	var actionID string
	for _, p := range s.teps.profiles {
		if p.SubjectTokenType == subjectType {
			actionID = p.ActionID
		}
	}
	s.teps.mu.RUnlock()
	if actionID == "" {
		return nil
	}
	a, ok := s.actions.get(actionID)
	if !ok || a.DeployedVersion == nil {
		return nil
	}
	return a
}

// exchangeThroughAction services a token exchange the way Auth0 does once a
// profile matches: the profile's Action decides the user, organization and
// actor, Auth0 checks them, post-login runs, and the token is issued.
func (s *Server) exchangeThroughAction(w http.ResponseWriter, r *http.Request, a *Action) {
	var sub string
	audience := exchangeAudience(r, s.cfg.Audience)
	failWith := func(status int, code, description string) {
		s.emitExchangeLog(r, "fecte", description, sub, "", audience, nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
	}
	fail := func(code, description string) { failWith(http.StatusBadRequest, code, description) }

	clientID := clientIDFromRequest(r)
	// Auth0 resolves the application before any Action runs.
	if s.lookupClient(clientID) == nil {
		failWith(http.StatusUnauthorized, "invalid_client", "Unknown client.")
		return
	}
	if r.FormValue("subject_token") == "" {
		fail("invalid_request", "subject_token is required")
		return
	}
	out, err := s.runExchangeAction(r, a, clientID, audience)
	switch {
	case err != nil:
		fail("invalid_request", fmt.Sprintf("action %s failed: %v", a.Name, err))
		return
	case out.code != "":
		fail(out.code, out.reason)
		return
	case out.userID == "":
		fail("invalid_request", "the action did not set a user")
		return
	}

	sub = out.userID
	s.mu.RLock()
	user, orgID, err := s.exchangeSubjectLocked(clientID, out)
	s.mu.RUnlock()
	if err != nil {
		fail("invalid_request", err.Error())
		return
	}

	now := time.Now()
	accessClaims := jwt.MapClaims{
		"sub":   user.ID,
		"iss":   s.cfg.Issuer,
		"aud":   audience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": grantedScope(r.FormValue("scope")),
	}
	if orgID != "" {
		accessClaims["org_id"] = orgID
	}
	if out.actor != nil {
		accessClaims["act"] = out.actor
	}
	idClaims := jwt.MapClaims{}
	if !s.postLogin(w, r, user, clientID, orgID, "", "oauth2-token-exchange", "", "", strings.Fields(r.FormValue("scope")), idClaims, accessClaims, func(req *postLoginRequest) {
		req.Actor, req.Metadata = out.actor, out.metadata
	}) {
		s.emitExchangeLog(r, "fecte", "post-login denied the exchange", sub, "", audience, nil)
		return
	}

	signed, err := s.SignToken(accessClaims)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	s.emitExchangeLog(r, "secte", "Successful token exchange", sub, orgID, audience, out.actor)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      signed,
		"issued_token_type": accessTokenType,
		"token_type":        "Bearer",
		"expires_in":        3600,
	})
}

// exchangeSubjectLocked applies the checks Auth0 makes on what the Action set:
// the user exists, their connection is enabled for the client, and an
// organization the Action named exists, has them as a member and has their
// connection enabled. Caller holds the read lock.
func (s *Server) exchangeSubjectLocked(clientID string, out exchangeOutcome) (*config.User, string, error) {
	u, ok := s.users[out.userID]
	if !ok {
		return nil, "", errors.New("user not found")
	}
	user := u.Clone()
	var conn *config.Connection
	if len(user.Identities) > 0 {
		conn = s.connectionByNameLocked(user.Identities[0].Connection)
	}
	if conn != nil && !slices.Contains(conn.EnabledClients, "*") && !slices.Contains(conn.EnabledClients, clientID) {
		return nil, "", fmt.Errorf("Unknown connection (%s) for client %s.", conn.Name, clientID) //nolint:staticcheck // Auth0's message
	}
	if out.org == "" {
		return user, "", nil
	}
	orgID := ""
	for id, o := range s.organizations {
		if id == out.org || o.Name == out.org {
			orgID = id
		}
	}
	if orgID == "" {
		return nil, "", errors.New("Organization not found") //nolint:staticcheck // Auth0's message
	}
	// Auth0 refuses setOrganization for a caller outside the organization
	// (stage, 2026-07); refusing a non-member target is the same rule.
	if !slices.ContainsFunc(s.members[orgID], func(m config.OrganizationMember) bool { return m.UserID == user.ID }) {
		return nil, "", errors.New("client requires organization membership, but user does not belong to the organization")
	}
	if conn != nil && !s.isConnectionEnabled(orgID, conn.ID) {
		return nil, "", errors.New("connection not enabled for this organization")
	}
	return user, orgID, nil
}

// runExchangeAction runs a custom-token-exchange Action and reports what its
// api calls set.
func (s *Server) runExchangeAction(r *http.Request, a *Action, clientID, audience string) (exchangeOutcome, error) {
	var out exchangeOutcome
	req := requestFromToken(r, "", "oauth2-token-exchange", strings.Fields(r.FormValue("scope")))
	refuse := func(code, reason string) {
		if out.code == "" {
			out.code, out.reason = code, reason
		}
	}
	err := s.runAction(a, nil, "onExecuteCustomTokenExchange", func(vm *goja.Runtime) (goja.Value, goja.Value) {
		client := map[string]any{"client_id": clientID, "name": "", "metadata": map[string]any{}}
		if c := s.lookupClient(clientID); c != nil {
			md := map[string]any{}
			for k, v := range c.ClientMetadata {
				md[k] = v
			}
			client["name"], client["metadata"] = c.Name, md
		}
		event := map[string]any{
			"client":          client,
			"request":         map[string]any{"body": req.Body, "method": req.Method, "ip": req.IP, "hostname": req.Host, "user_agent": req.UA, "geoip": map[string]any{}},
			"resource_server": map[string]any{"identifier": audience},
			"transaction": map[string]any{
				"subject_token":      r.FormValue("subject_token"),
				"subject_token_type": r.FormValue("subject_token_type"),
				"requested_scopes":   req.Scopes,
			},
			"tenant":  map[string]any{"id": "mock"},
			"secrets": secretValues(a, nil),
		}

		access := vm.NewObject()
		_ = access.Set("deny", refuse)
		_ = access.Set("rejectInvalidSubjectToken", func(reason string) { refuse("invalid_request", reason) })
		auth := vm.NewObject()
		_ = auth.Set("setUserById", func(id string) { out.userID = id })
		_ = auth.Set("setUserByConnection", func() {
			panic(vm.NewGoError(errors.New("setUserByConnection is not available in the auth0 mock")))
		})
		_ = auth.Set("setOrganization", func(org string) { out.org = org })
		_ = auth.Set("setActor", func(actor map[string]any) { out.actor = actor })
		tx := vm.NewObject()
		_ = tx.Set("setMetadata", func(key string, value goja.Value) {
			if out.metadata == nil {
				out.metadata = map[string]any{}
			}
			out.metadata[key] = value.Export()
		})
		api := vm.NewObject()
		_ = api.Set("access", access)
		_ = api.Set("authentication", auth)
		_ = api.Set("transaction", tx)
		return vm.ToValue(event), api
	})
	return out, err
}

// exchangeAudience is the API the exchange asks for, else the tenant default.
func exchangeAudience(r *http.Request, fallback string) string {
	if a := r.FormValue("audience"); a != "" {
		return a
	}
	return fallback
}
