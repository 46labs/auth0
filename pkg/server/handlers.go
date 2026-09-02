package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

// parseTokenBody normalizes form vs JSON bodies into r.Form so the existing
// FormValue() call sites in handleToken work for both encodings. Auth0.swift
// posts application/json; web SPA and go-auth0 post x-www-form-urlencoded.
func parseTokenBody(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct != "application/json" {
		return r.ParseForm()
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer func() { _ = r.Body.Close() }()
	r.Form = url.Values{}
	if len(body) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return err
	}
	for k, v := range m {
		switch t := v.(type) {
		case string:
			r.Form.Set(k, t)
		case float64:
			r.Form.Set(k, strconv.FormatFloat(t, 'f', -1, 64))
		case bool:
			r.Form.Set(k, strconv.FormatBool(t))
		}
	}
	return nil
}

// parseRedirectURI parses a redirect_uri and restores the original scheme
// casing. url.Parse normalizes the scheme to lowercase per RFC 3986, but
// iOS ASWebAuthenticationSession matches `callbackURLScheme` case-sensitively
// at the OS level. Native iOS app callbacks use the bundle identifier as the
// scheme (e.g. `com.pl8txt.Pl8txt://…`), so lowercasing breaks the round-trip.
// Real Auth0 preserves the original case; this matches that behavior.
func parseRedirectURI(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	if i := strings.Index(raw, ":"); i > 0 {
		u.Scheme = raw[:i]
	}
	return u
}

// clientIDFromRequest reads the client from the body, then HTTP Basic.
// x/oauth2 probes both styles, so a body-only read misidentifies the caller.
func clientIDFromRequest(r *http.Request) string {
	if id := r.FormValue("client_id"); id != "" {
		return id
	}
	if id, _, ok := r.BasicAuth(); ok {
		return id
	}
	return ""
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Issuer + "authorize",
		"token_endpoint":                        s.cfg.Issuer + "oauth/token",
		"userinfo_endpoint":                     s.cfg.Issuer + "userinfo",
		"jwks_uri":                              s.cfg.Issuer + ".well-known/jwks.json",
		"end_session_endpoint":                  s.cfg.Issuer + "v2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	pub := &s.privateKey.PublicKey
	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": "key-1",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []interface{}{jwk},
	})
}

// redirectAuthorizeError reports failure through the application's
// redirect_uri, falling back to 400 when there is no usable target.
func (s *Server) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, code, description string) {
	// A missing target is a malformed request, not the failure being reported.
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"redirect_uri is required"}`,
			http.StatusBadRequest)
		return
	}
	u := parseRedirectURI(redirectURI)
	if u == nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if state := r.URL.Query().Get("state"); state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Handle prompt=none (silent auth check from SDK iframes).
		// No server-side sessions exist in the mock, so always return login_required.
		if r.URL.Query().Get("prompt") == "none" {
			s.redirectAuthorizeError(w, r, "login_required", "Login required")
			return
		}

		loginHint := r.URL.Query().Get("login_hint")

		// Validate before rendering the page, so a revoked or expired ticket
		// fails immediately rather than after a code is entered. The invited
		// address becomes the login hint, as Auth0 prefills it.
		if ticket, ok := ticketFromQuery(r.URL.Query()); ok {
			s.mu.Lock()
			inv, err := s.lookupInvitation(ticket, time.Now())
			var invitee string
			if err == nil {
				invitee = inv.InviteeEmail
			}
			s.mu.Unlock()

			if err != nil {
				s.redirectAuthorizeError(w, r, "invalid_request", err.Error())
				return
			}
			loginHint = invitee
		} else if orgID := r.URL.Query().Get("organization"); orgID != "" {
			// Membership needs an authenticated user, but an unknown org can
			// be refused before the login page.
			s.mu.RLock()
			_, known := s.organizations[orgID]
			s.mu.RUnlock()
			if !known {
				s.redirectAuthorizeError(w, r, "invalid_request", errOrgNotFound.Error())
				return
			}
		}

		sessionID := s.generateID()
		s.mu.Lock()
		s.pending[sessionID] = r.URL.RawQuery
		s.mu.Unlock()

		data := map[string]interface{}{
			"SessionID": sessionID,
			"Branding":  s.cfg.Branding,
			"LoginHint": loginHint,
		}

		w.Header().Set("Content-Type", "text/html")
		_ = s.templates.Execute(w, data)
		return
	}

	if r.Method == "POST" {
		_ = r.ParseForm()
		sessionID := r.FormValue("session_id")
		identifier := r.FormValue("identifier")
		if identifier == "" {
			identifier = r.FormValue("phone")
		}
		if identifier == "" {
			identifier = r.FormValue("email")
		}
		code := r.FormValue("code")

		s.mu.RLock()
		originalQuery, exists := s.pending[sessionID]
		s.mu.RUnlock()
		if !exists {
			http.Error(w, "Invalid session", 400)
			return
		}

		if code != "" {
			if code != "123456" {
				http.Error(w, "Invalid code", 400)
				return
			}

			params, _ := url.ParseQuery(originalQuery)

			// Validate before minting, so a bad redirect_uri cannot leave an
			// orphaned auth code behind.
			redirectURI := params.Get("redirect_uri")
			redirectURL := parseRedirectURI(redirectURI)
			if redirectURL == nil {
				http.Error(w, "Invalid redirect_uri", 400)
				return
			}

			// Auth0 owns acceptance: validate the ticket, create the user when
			// new, join the org, assign the role, consume the ticket.
			var user *config.User
			orgID := params.Get("organization")

			if ticket, ok := ticketFromQuery(params); ok {
				redeemed, err := s.redeemInvitation(ticket, identifier, time.Now())
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				user = redeemed
				orgID = ticket.OrgID
			} else {
				user = s.findUser(identifier)
				// Auto-create user if not found (like real Auth0 passwordless)
				if user == nil {
					user = s.autoCreateUser(identifier)
				}
				if user == nil {
					http.Error(w, "Invalid code", 400)
					return
				}

				if err := s.authorizeOrgLogin(user, orgID); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			if user == nil {
				http.Error(w, "Invalid code", 400)
				return
			}

			code := s.generateID()
			state := &authCode{
				User:          *user,
				CodeChallenge: params.Get("code_challenge"),
				Nonce:         params.Get("nonce"),
				Scope:         params.Get("scope"),
				ClientID:      params.Get("client_id"),
				OrgID:         orgID,
			}

			s.mu.Lock()
			s.authCodes[code] = state
			delete(s.pending, sessionID)
			s.mu.Unlock()

			query := redirectURL.Query()
			query.Set("code", code)
			if st := params.Get("state"); st != "" {
				query.Set("state", st)
			}
			redirectURL.RawQuery = query.Encode()

			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return
		}

		data := map[string]interface{}{
			"SessionID": sessionID,
			"Branding":  s.cfg.Branding,
		}
		w.Header().Set("Content-Type", "text/html")
		_ = s.templates.Execute(w, data)
	}
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Auth0-Client")

	if r.Method == "OPTIONS" {
		return
	}

	_ = parseTokenBody(r)
	grantType := r.FormValue("grant_type")
	clientID := clientIDFromRequest(r)

	// Handle client_credentials flow for M2M
	if grantType == "client_credentials" {
		clientSecret := r.FormValue("client_secret")
		audience := r.FormValue("audience")
		organization := r.FormValue("organization")

		// Validate client credentials against configured clients
		s.mu.RLock()
		client, exists := s.clients[clientID]
		s.mu.RUnlock()

		if !exists || client.ClientSecret != clientSecret {
			http.Error(w, `{"error":"invalid_client","error_description":"Invalid client_id or client_secret"}`, http.StatusUnauthorized)
			return
		}

		// Validate organization exists if provided (matches real Auth0 behavior)
		if organization != "" {
			s.mu.RLock()
			_, orgExists := s.organizations[organization]
			s.mu.RUnlock()
			if !orgExists {
				http.Error(w, `{"error":"invalid_request","error_description":"Organization not found"}`, 400)
				return
			}
		}

		now := time.Now()
		accessClaims := jwt.MapClaims{
			"sub":       clientID,
			"iss":       s.cfg.Issuer,
			"aud":       audience,
			"exp":       now.Add(24 * time.Hour).Unix(),
			"iat":       now.Unix(),
			"scope":     "read:organizations write:organizations read:users write:users",
			"gty":       "client-credentials",
			"client_id": clientID,
		}

		// Include org_id in token when organization is requested (matches real Auth0)
		if organization != "" {
			accessClaims["org_id"] = organization
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
		accessToken.Header["kid"] = "key-1"

		accessTokenString, err := accessToken.SignedString(s.privateKey)
		if err != nil {
			http.Error(w, "Token generation failed", 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessTokenString,
			"token_type":   "Bearer",
			"expires_in":   86400,
			"scope":        "read:organizations write:organizations read:users write:users",
		})
		return
	}

	// Handle refresh_token flow
	if grantType == "refresh_token" {
		refreshToken := r.FormValue("refresh_token")
		if refreshToken == "" {
			http.Error(w, `{"error":"invalid_request","error_description":"refresh_token is required"}`, 400)
			return
		}

		s.mu.RLock()
		issued, exists := s.refreshTokens[refreshToken]
		s.mu.RUnlock()

		if !exists {
			http.Error(w, `{"error":"invalid_grant","error_description":"Invalid refresh token"}`, 400)
			return
		}

		// Load first: the account can be deleted while its refresh token lives.
		user := s.getUserByID(issued.UserID)
		if user == nil {
			http.Error(w, `{"error":"invalid_grant","error_description":"User not found"}`, 400)
			return
		}

		// The org is the one the original login was scoped to.
		orgID := issued.OrgID
		if orgID == "" {
			orgID = user.AppMetadata.TenantID()
		}

		if seeded := s.seedOrgRoles(issued.UserID, orgID); seeded != nil {
			user = seeded
		}

		now := time.Now()
		ns := strings.TrimSuffix(s.cfg.Issuer, "/") + "/"

		// Generate new access token
		accessClaims := jwt.MapClaims{
			"sub":   user.ID,
			"iss":   s.cfg.Issuer,
			"aud":   s.cfg.Audience,
			"exp":   now.Add(time.Hour).Unix(),
			"iat":   now.Unix(),
			"scope": "openid profile email",
		}

		if orgID != "" {
			accessClaims["org_id"] = orgID
		}
		if role := roleForOrg(user, orgID); role != "" {
			accessClaims[ns+"role"] = role
		}

		idClaims := jwt.MapClaims{
			"sub":            user.ID,
			"email":          user.Email,
			"email_verified": user.EmailVerified,
			"name":           user.Name,
			"iss":            s.cfg.Issuer,
			"aud":            clientID,
			"exp":            now.Add(time.Hour).Unix(),
			"iat":            now.Unix(),
		}

		if user.Phone != "" {
			idClaims["phone_number"] = user.Phone
			idClaims["phone_number_verified"] = true
		}

		if user.Picture != "" {
			idClaims["picture"] = user.Picture
		}

		nameParts := strings.Split(user.Name, " ")
		if len(nameParts) > 0 {
			idClaims["given_name"] = nameParts[0]
		}
		if len(nameParts) > 1 {
			idClaims["family_name"] = nameParts[1]
		}

		// org_id is a top-level claim (matches production Auth0 Organizations)
		if orgID != "" {
			idClaims["org_id"] = orgID
		}
		// role remains namespaced (requires Auth0 Action in production)
		if role := roleForOrg(user, orgID); role != "" {
			idClaims[ns+"role"] = role
		}

		s.applyPostLogin(user, s.lookupClient(clientID), orgID, idClaims, accessClaims)

		accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
		accessToken.Header["kid"] = "key-1"

		accessTokenString, err := accessToken.SignedString(s.privateKey)
		if err != nil {
			http.Error(w, "Token generation failed", 500)
			return
		}

		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
		idToken.Header["kid"] = "key-1"

		idTokenString, err := idToken.SignedString(s.privateKey)
		if err != nil {
			http.Error(w, "Token generation failed", 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  accessTokenString,
			"id_token":      idTokenString,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": refreshToken, // Return the same refresh token
		})
		return
	}

	// Handle RFC 8693 token exchange (Auth0 Custom Token Exchange). Mirrors an
	// on-behalf-of exchange: a subject token is traded for a token scoped to a
	// target organization, carrying a delegated actor (`act`) claim for audit.
	if grantType == tokenExchangeGrantType {
		s.handleTokenExchange(w, r)
		return
	}

	// Handle authorization_code flow (existing logic)
	code := r.FormValue("code")

	// Claim the code atomically: codes are single-use, so a concurrent second
	// exchange must lose rather than race the delete. The client check sits
	// before the delete so a rejected exchange does not burn the code —
	// clients probing both auth styles would consume it on the losing attempt.
	s.mu.Lock()
	claimed, exists := s.authCodes[code]
	wrongClient := exists && claimed.ClientID != "" && clientID != claimed.ClientID
	if exists && !wrongClient {
		delete(s.authCodes, code)
	}
	s.mu.Unlock()

	if !exists {
		http.Error(w, "Invalid code", 400)
		return
	}
	if wrongClient {
		http.Error(w,
			`{"error":"invalid_grant","error_description":"the code was issued to a different client"}`,
			http.StatusBadRequest)
		return
	}

	user := claimed.User
	nonce, hasNonce := claimed.Nonce, claimed.Nonce != ""
	requestedScope := claimed.Scope

	// The scoped organization wins over the stored tenant, so a member of
	// several gets a token for the one they logged in to.
	orgID := claimed.OrgID
	if orgID == "" {
		orgID = user.AppMetadata.TenantID()
	}

	// Post-Login Action parity, and it reads back the latest AppMetadata.
	if seeded := s.seedOrgRoles(user.ID, orgID); seeded != nil {
		user = *seeded
	} else if latestUser := s.getUserByID(user.ID); latestUser != nil {
		user = *latestUser
	}

	now := time.Now()
	ns := strings.TrimSuffix(s.cfg.Issuer, "/") + "/"

	idClaims := jwt.MapClaims{
		"sub":            user.ID,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"name":           user.Name,
		"iss":            s.cfg.Issuer,
		"aud":            clientID,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"auth_time":      now.Unix(),
	}

	if user.Phone != "" {
		idClaims["phone_number"] = user.Phone
		idClaims["phone_number_verified"] = true
	}

	if user.Picture != "" {
		idClaims["picture"] = user.Picture
	}

	if hasNonce {
		idClaims["nonce"] = nonce
	}

	nameParts := strings.Split(user.Name, " ")
	if len(nameParts) > 0 {
		idClaims["given_name"] = nameParts[0]
	}
	if len(nameParts) > 1 {
		idClaims["family_name"] = nameParts[1]
	}

	if orgID != "" {
		idClaims["org_id"] = orgID
	}
	if role := roleForOrg(&user, orgID); role != "" {
		idClaims[ns+"role"] = role
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	idToken.Header["kid"] = "key-1"

	accessClaims := jwt.MapClaims{
		"sub":   user.ID,
		"iss":   s.cfg.Issuer,
		"aud":   s.cfg.Audience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "openid profile email",
	}

	// org_id is a top-level claim (matches production Auth0 Organizations)
	if orgID != "" {
		accessClaims["org_id"] = orgID
	}
	// role remains namespaced (requires Auth0 Action in production)
	if role := roleForOrg(&user, orgID); role != "" {
		accessClaims[ns+"role"] = role
	}

	s.applyPostLogin(&user, s.lookupClient(clientID), orgID, idClaims, accessClaims)

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = "key-1"

	idTokenString, err := idToken.SignedString(s.privateKey)
	if err != nil {
		http.Error(w, "Token generation failed", 500)
		return
	}

	accessTokenString, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		http.Error(w, "Token generation failed", 500)
		return
	}

	// The scope was captured when the code was claimed above.
	var refreshToken string
	if strings.Contains(requestedScope, "offline_access") {
		refreshToken = "rt_" + base64.RawURLEncoding.EncodeToString([]byte(s.generateID()))
		s.mu.Lock()
		s.refreshTokens[refreshToken] = &refreshTokenState{UserID: user.ID, OrgID: orgID}
		s.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"access_token": accessTokenString,
		"id_token":     idTokenString,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	if refreshToken != "" {
		response["refresh_token"] = refreshToken
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || auth[:7] != "Bearer " {
		http.Error(w, "Invalid authorization", http.StatusUnauthorized)
		return
	}

	tokenString := auth[7:]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &s.privateKey.PublicKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":          claims["sub"],
		"email":        claims["email"],
		"name":         claims["name"],
		"phone_number": claims["phone_number"],
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("returnTo")
	if returnTo == "" {
		returnTo = strings.TrimSuffix(s.cfg.Issuer, "/")
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}
