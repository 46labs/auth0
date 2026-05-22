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

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Handle prompt=none (silent auth check from SDK iframes).
		// No server-side sessions exist in the mock, so always return login_required.
		if r.URL.Query().Get("prompt") == "none" {
			redirectURI := r.URL.Query().Get("redirect_uri")
			if redirectURI == "" {
				http.Error(w, `{"error":"invalid_request"}`, 400)
				return
			}
			u := parseRedirectURI(redirectURI)
			if u == nil {
				http.Error(w, `{"error":"invalid_request"}`, 400)
				return
			}
			q := u.Query()
			q.Set("error", "login_required")
			q.Set("error_description", "Login required")
			if state := r.URL.Query().Get("state"); state != "" {
				q.Set("state", state)
			}
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}

		sessionID := s.generateID()
		s.pending[sessionID] = r.URL.RawQuery

		loginHint := r.URL.Query().Get("login_hint")
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

		originalQuery, exists := s.pending[sessionID]
		if !exists {
			http.Error(w, "Invalid session", 400)
			return
		}

		if code != "" {
			if code == "123456" {
				user := s.findUser(identifier)
				// Auto-create user if not found (like real Auth0 passwordless)
				if user == nil {
					user = s.autoCreateUser(identifier)
				}
				if user != nil {
					params, _ := url.ParseQuery(originalQuery)
					authCode := s.generateID()
					s.verified[authCode] = *user

					if codeChallenge := params.Get("code_challenge"); codeChallenge != "" {
						s.verifiers[authCode] = codeChallenge
					}
					if nonce := params.Get("nonce"); nonce != "" {
						s.nonces[authCode] = nonce
					}
					if scope := params.Get("scope"); scope != "" {
						s.scopes[authCode] = scope
					}

					redirectURI := params.Get("redirect_uri")
					redirectURL := parseRedirectURI(redirectURI)
					if redirectURL == nil {
						http.Error(w, "Invalid redirect_uri", 400)
						return
					}
					query := redirectURL.Query()
					query.Set("code", authCode)
					if state := params.Get("state"); state != "" {
						query.Set("state", state)
					}
					redirectURL.RawQuery = query.Encode()

					delete(s.pending, sessionID)
					http.Redirect(w, r, redirectURL.String(), http.StatusFound)
					return
				}
			}
			http.Error(w, "Invalid code", 400)
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
	clientID := r.FormValue("client_id")

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
		userID, exists := s.refreshTokens[refreshToken]
		s.mu.RUnlock()

		if !exists {
			http.Error(w, `{"error":"invalid_grant","error_description":"Invalid refresh token"}`, 400)
			return
		}

		user := s.getUserByID(userID)
		if user == nil {
			http.Error(w, `{"error":"invalid_grant","error_description":"User not found"}`, 400)
			return
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

		if user.AppMetadata.TenantID != "" {
			accessClaims["org_id"] = user.AppMetadata.TenantID
		}
		if user.AppMetadata.Role != "" {
			accessClaims[ns+"role"] = user.AppMetadata.Role
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
		if user.AppMetadata.TenantID != "" {
			idClaims["org_id"] = user.AppMetadata.TenantID
		}
		// role remains namespaced (requires Auth0 Action in production)
		if user.AppMetadata.Role != "" {
			idClaims[ns+"role"] = user.AppMetadata.Role
		}

		s.applyPostLogin(user, s.lookupClient(clientID), idClaims, accessClaims)

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

	// Handle authorization_code flow (existing logic)
	code := r.FormValue("code")
	user, exists := s.verified[code]
	if !exists {
		http.Error(w, "Invalid code", 400)
		return
	}

	// Always get the latest user data from s.users to include updated AppMetadata
	if latestUser := s.getUserByID(user.ID); latestUser != nil {
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

	if nonce, ok := s.nonces[code]; ok {
		idClaims["nonce"] = nonce
	}

	nameParts := strings.Split(user.Name, " ")
	if len(nameParts) > 0 {
		idClaims["given_name"] = nameParts[0]
	}
	if len(nameParts) > 1 {
		idClaims["family_name"] = nameParts[1]
	}

	if user.AppMetadata.TenantID != "" {
		idClaims["org_id"] = user.AppMetadata.TenantID
	}
	if user.AppMetadata.Role != "" {
		idClaims[ns+"role"] = user.AppMetadata.Role
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
	if user.AppMetadata.TenantID != "" {
		accessClaims["org_id"] = user.AppMetadata.TenantID
	}
	// role remains namespaced (requires Auth0 Action in production)
	if user.AppMetadata.Role != "" {
		accessClaims[ns+"role"] = user.AppMetadata.Role
	}

	s.applyPostLogin(&user, s.lookupClient(clientID), idClaims, accessClaims)

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

	// Generate refresh token if offline_access scope was requested
	s.mu.Lock()
	requestedScope := s.scopes[code]
	var refreshToken string
	if strings.Contains(requestedScope, "offline_access") {
		refreshToken = "rt_" + base64.RawURLEncoding.EncodeToString([]byte(s.generateID()))
		s.refreshTokens[refreshToken] = user.ID
	}
	s.mu.Unlock()

	delete(s.verified, code)
	delete(s.verifiers, code)
	delete(s.nonces, code)
	delete(s.scopes, code)

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
