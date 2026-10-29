package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// tokenExchangeGrantType is the RFC 8693 token-exchange grant.
	tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// accessTokenType is the RFC 8693 access-token type URN.
	accessTokenType = "urn:ietf:params:oauth:token-type:access_token"
)

// handleTokenExchange services RFC 8693 token exchange (Auth0 Custom Token
// Exchange). It trades a subject token for a new access token scoped to a
// requested target organization, per the config-driven TokenExchangeAction.
// The minted token keeps the subject's sub (the real operator), sets
// org_id to the target, and carries a delegated `act` claim for audit. All
// consumer-specific claim names come from config; this code stays generic.
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	// A profile for the subject token type routes the exchange to its Action,
	// as in Auth0; the configured stand-in serves tenants without one.
	if a := s.profileAction(r.FormValue("subject_token_type")); a != nil {
		s.exchangeThroughAction(w, r, a)
		return
	}
	ex := s.cfg.Actions.TokenExchange
	if ex == nil {
		http.Error(w, `{"error":"unsupported_grant_type","error_description":"token exchange not configured"}`, http.StatusBadRequest)
		return
	}

	// Every outcome past this point is a Custom Token Exchange transaction,
	// which Auth0 logs as secte or fecte.
	var sub string
	fail := func(status int, body, description string) {
		s.emitExchangeLog(r, "fecte", description, sub, "", s.cfg.Audience, nil)
		http.Error(w, body, status)
	}

	// Match the profile's subject_token_type, as Auth0 routes exchanges to a
	// profile by this value (and rejects reserved namespaces at config time).
	if ex.SubjectTokenType != "" && r.FormValue("subject_token_type") != ex.SubjectTokenType {
		fail(http.StatusBadRequest, `{"error":"invalid_request","error_description":"no token exchange profile for subject_token_type"}`, "no token exchange profile for subject_token_type")
		return
	}

	subjectToken := r.FormValue("subject_token")
	// Target tenant rides as a custom body param the Auth0 CTE Action reads from
	// event.request.body.target_org (then calls api.authentication.setOrganization).
	organization := r.FormValue("target_org")
	if subjectToken == "" {
		fail(http.StatusBadRequest, `{"error":"invalid_request","error_description":"subject_token is required"}`, "subject_token is required")
		return
	}
	if organization == "" {
		fail(http.StatusBadRequest, `{"error":"invalid_request","error_description":"target_org is required"}`, "target_org is required")
		return
	}

	s.mu.RLock()
	_, orgExists := s.organizations[organization]
	s.mu.RUnlock()
	if !orgExists {
		fail(http.StatusBadRequest, `{"error":"invalid_request","error_description":"Organization not found"}`, "Organization not found")
		return
	}

	// Verify the subject token's signature and expiry against our signing key.
	subClaims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(subjectToken, subClaims, func(*jwt.Token) (interface{}, error) {
		return &s.privateKey.PublicKey, nil
	})
	if err != nil || !tok.Valid {
		fail(http.StatusBadRequest, `{"error":"invalid_grant","error_description":"subject_token invalid"}`, "subject_token invalid")
		return
	}
	sub, _ = subClaims["sub"].(string)
	if sub == "" {
		fail(http.StatusBadRequest, `{"error":"invalid_grant","error_description":"subject_token missing sub"}`, "subject_token missing sub")
		return
	}

	// Authorization gate: the Action's stand-in. Only subjects whose token
	// carries the required claim non-empty may exchange.
	if ex.RequireClaim != "" {
		if v, _ := subClaims[ex.RequireClaim].(string); v == "" {
			fail(http.StatusForbidden, `{"error":"access_denied","error_description":"subject not permitted to exchange"}`, "subject not permitted to exchange")
			return
		}
	}

	now := time.Now()
	minted := jwt.MapClaims{
		"sub":   sub,
		"iss":   s.cfg.Issuer,
		"aud":   s.accessAudience(s.cfg.Audience, "openid profile email"),
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "openid profile email",
	}
	// The stand-in predates client checks and its callers send no client_id;
	// it names only a registered client.
	if clientID := clientIDFromRequest(r); s.lookupClient(clientID) != nil {
		minted["azp"] = clientID
	}

	orgClaim := ex.OrgClaim
	if orgClaim == "" {
		orgClaim = "org_id"
	}
	minted[orgClaim] = organization
	// Overlays must not reach the organization: real Auth0 cannot issue a native
	// org_id for a non-member, and the subject's own would scope the token to
	// where the caller came from.
	orgKeys := map[string]bool{orgClaim: true, "org_id": true}
	for _, k := range ex.CarryClaims {
		if orgKeys[k] {
			continue
		}
		if v, ok := subClaims[k]; ok {
			minted[k] = v
		}
	}
	for k, v := range ex.SetClaims {
		if orgKeys[k] {
			continue
		}
		minted[k] = v
	}
	if ex.Actor {
		minted["act"] = map[string]interface{}{"sub": sub}
	}

	signed, err := s.SignToken(minted)
	if err != nil {
		fail(http.StatusInternalServerError, "Token generation failed", "Token generation failed")
		return
	}

	// Auth0 logs an organization only when the exchange sets one natively.
	nativeOrg := ""
	if orgClaim == "org_id" {
		nativeOrg = organization
	}
	var actor map[string]any
	if ex.Actor {
		actor = map[string]any{"sub": sub}
	}
	s.emitExchangeLog(r, "secte", "Successful token exchange", sub, nativeOrg, s.cfg.Audience, actor)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":      signed,
		"issued_token_type": accessTokenType,
		"token_type":        "Bearer",
		"expires_in":        3600,
	})
}
