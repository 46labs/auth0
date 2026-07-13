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
	ex := s.cfg.Actions.TokenExchange
	if ex == nil {
		http.Error(w, `{"error":"unsupported_grant_type","error_description":"token exchange not configured"}`, http.StatusBadRequest)
		return
	}

	// Match the profile's subject_token_type, as Auth0 routes exchanges to a
	// profile by this value (and rejects reserved namespaces at config time).
	if ex.SubjectTokenType != "" && r.FormValue("subject_token_type") != ex.SubjectTokenType {
		http.Error(w, `{"error":"invalid_request","error_description":"no token exchange profile for subject_token_type"}`, http.StatusBadRequest)
		return
	}

	subjectToken := r.FormValue("subject_token")
	// Target tenant rides as a custom body param the Auth0 CTE Action reads from
	// event.request.body.target_org (then calls api.authentication.setOrganization).
	organization := r.FormValue("target_org")
	if subjectToken == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"subject_token is required"}`, http.StatusBadRequest)
		return
	}
	if organization == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"target_org is required"}`, http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	_, orgExists := s.organizations[organization]
	s.mu.RUnlock()
	if !orgExists {
		http.Error(w, `{"error":"invalid_request","error_description":"Organization not found"}`, http.StatusBadRequest)
		return
	}

	// Verify the subject token's signature and expiry against our signing key.
	subClaims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(subjectToken, subClaims, func(*jwt.Token) (interface{}, error) {
		return &s.privateKey.PublicKey, nil
	})
	if err != nil || !tok.Valid {
		http.Error(w, `{"error":"invalid_grant","error_description":"subject_token invalid"}`, http.StatusBadRequest)
		return
	}
	sub, _ := subClaims["sub"].(string)
	if sub == "" {
		http.Error(w, `{"error":"invalid_grant","error_description":"subject_token missing sub"}`, http.StatusBadRequest)
		return
	}

	// Authorization gate: the Action's stand-in. Only subjects whose token
	// carries the required claim non-empty may exchange.
	if ex.RequireClaim != "" {
		if v, _ := subClaims[ex.RequireClaim].(string); v == "" {
			http.Error(w, `{"error":"access_denied","error_description":"subject not permitted to exchange"}`, http.StatusForbidden)
			return
		}
	}

	now := time.Now()
	minted := jwt.MapClaims{
		"sub":    sub,
		"iss":    s.cfg.Issuer,
		"aud":    s.cfg.Audience,
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"scope":  "openid profile email",
		"org_id": organization,
	}
	for _, k := range ex.CarryClaims {
		if v, ok := subClaims[k]; ok {
			minted[k] = v
		}
	}
	for k, v := range ex.SetClaims {
		minted[k] = v
	}
	if ex.Actor {
		minted["act"] = map[string]interface{}{"sub": sub}
	}

	at := jwt.NewWithClaims(jwt.SigningMethodRS256, minted)
	at.Header["kid"] = "key-1"
	signed, err := at.SignedString(s.privateKey)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":      signed,
		"issued_token_type": accessTokenType,
		"token_type":        "Bearer",
		"expires_in":        3600,
	})
}
