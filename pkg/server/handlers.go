package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/url"
	"slices"
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
		"device_authorization_endpoint":         s.cfg.Issuer + "oauth/device/code",
		"userinfo_endpoint":                     s.cfg.Issuer + "userinfo",
		"jwks_uri":                              s.cfg.Issuer + ".well-known/jwks.json",
		"end_session_endpoint":                  s.cfg.Issuer + "v2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token", deviceCodeGrantType},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone", "offline_access"},
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
				// Refused before any credential is entered, so no user is known.
				s.emitLoginLog(r, r.URL.Query(), "f", err.Error(), nil, "", ticket.OrgID)
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
				s.emitLoginLog(r, r.URL.Query(), "f", errOrgNotFound.Error(), nil, "", orgID)
				s.redirectAuthorizeError(w, r, "invalid_request", errOrgNotFound.Error())
				return
			}
		}

		// Auth0 refuses an audience no API on the tenant has.
		if aud := r.URL.Query().Get("audience"); aud != "" && !s.knownAudience(aud) {
			s.redirectAuthorizeError(w, r, "access_denied", "Service not found: "+aud)
			return
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
			params, _ := url.ParseQuery(originalQuery)
			// The ticket's connection is authoritative for an invitation, so
			// every log of this attempt names it rather than the user's identity.
			logParams := params
			if ticket, ok := ticketFromQuery(params); ok {
				if name := s.invitationConnectionName(ticket); name != "" {
					logParams = maps.Clone(params)
					logParams.Set("connection", name)
				}
			}

			if code != passwordlessCode {
				s.emitLoginLog(r, logParams, "f", "Wrong email or verification code.", s.findUser(identifier), identifier, params.Get("organization"))
				http.Error(w, "Invalid code", 400)
				return
			}

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
			connectionID := params.Get("connection")
			var resolved string

			if ticket, ok := ticketFromQuery(params); ok {
				redeemed, via, err := s.redeemInvitation(ticket, identifier, time.Now())
				if err != nil {
					s.emitLoginLog(r, logParams, "f", err.Error(), s.findUser(identifier), identifier, ticket.OrgID)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				user, resolved = redeemed, via
				orgID = ticket.OrgID
			} else {
				var err error
				if user, resolved, err = s.loginUser(identifier, connectionID, params.Get("client_id"), orgID); err != nil {
					s.emitLoginLog(r, logParams, "f", err.Error(), nil, identifier, orgID)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				if err := s.authorizeOrgLogin(user, orgID, connectionID); err != nil {
					s.emitLoginLog(r, logParams, "f", err.Error(), user, identifier, orgID)
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
				ConnectionID:  connectionID,
				Connection:    resolved,
				Query:         originalQuery,
				SessionID:     "sess_" + s.generateID(),
				LoginLog:      s.loginLog(r, withConnection(logParams, resolved), "s", "Successful login", user, identifier, orgID),
			}

			s.mu.Lock()
			s.authCodes[code] = state
			delete(s.pending, sessionID)
			s.recordLoginLocked(user.ID, identifier, resolved)
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

		// A copy, since updates mutate the stored client under the write lock.
		client := s.lookupClient(clientID)
		if client == nil || client.ClientSecret != clientSecret {
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
			"azp":       clientID,
			"client_id": clientID,
		}

		// Include org_id in token when organization is requested (matches real Auth0)
		if organization != "" {
			accessClaims["org_id"] = organization
		}

		// A credentials-exchange action stamps claims from the application's
		// metadata, which is how an M2M credential carries an organization when
		// the grant cannot enter an organization context.
		s.applyCredentialsExchange(client, accessClaims)

		accessTokenString, err := s.SignToken(accessClaims)
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
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
			return
		}

		issued, release, errDescription, errStatus := s.claimRefreshToken(refreshToken, clientID, time.Now())
		defer release()
		if issued == nil {
			writeOAuthError(w, errStatus, "invalid_grant", errDescription)
			return
		}
		// A refresh may narrow the scope it was granted, never widen it.
		scope := issued.Scope
		// A blank scope is an absent one, never the default scopes.
		if requested := strings.Fields(r.FormValue("scope")); len(requested) > 0 {
			if !scopeWithin(requested, issued.Scope) {
				writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "the scope exceeds the one granted")
				return
			}
			scope = strings.Join(requested, " ")
		}

		// Load first: the account can be deleted while its refresh token lives.
		user := s.getUserByID(issued.UserID)
		if user == nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "User not found")
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

		// Generate new access token
		audience := issued.Audience
		if audience == "" {
			audience = s.cfg.Audience
		}
		accessClaims := s.accessTokenClaims(user, clientID, audience, scope, orgID, now)
		idClaims := s.idTokenClaims(user, clientID, orgID, now)

		if issued.SessionID != "" {
			idClaims["sid"] = issued.SessionID
		}
		if !s.postLogin(w, r, user, clientID, orgID, "", "oauth2-refresh-token", issued.SessionID, issued.Connection, strings.Fields(scope), idClaims, accessClaims) {
			return
		}

		accessTokenString, err := s.SignToken(accessClaims)
		if err != nil {
			http.Error(w, "Token generation failed", 500)
			return
		}
		// Rotated only now, so a refused refresh leaves the client its token.
		rotated, errDescription, errStatus := s.rotateRefreshToken(refreshToken, issued)
		if errDescription != "" {
			writeOAuthError(w, errStatus, "invalid_grant", errDescription)
			return
		}

		response := map[string]interface{}{
			"access_token": accessTokenString,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        grantedScope(scope),
		}
		// Auth0 returns a refresh token on a refresh only with rotation.
		// Without it the response has none and the redeemed token stays valid.
		if rotated != "" {
			response["refresh_token"] = rotated
		}
		if issued.IncludeIDToken && hasScope(scope, "openid") {
			idTokenString, err := s.SignToken(idClaims)
			if err != nil {
				http.Error(w, "Token generation failed", 500)
				return
			}
			response["id_token"] = idTokenString
		}
		writeOAuthJSON(w, http.StatusOK, response)
		return
	}

	if grantType == deviceCodeGrantType {
		s.handleDeviceToken(w, r, clientID)
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

	idClaims := s.idTokenClaims(&user, clientID, orgID, now)
	idClaims["auth_time"] = now.Unix()
	if hasNonce {
		idClaims["nonce"] = nonce
	}

	audience := s.authorizeAudience(claimed.Query)
	accessClaims := s.accessTokenClaims(&user, clientID, audience, requestedScope, orgID, now)

	if claimed.SessionID != "" {
		idClaims["sid"] = claimed.SessionID
	}
	allowed := s.postLogin(w, r, &user, clientID, orgID, claimed.Query, "oidc-basic-profile", claimed.SessionID, claimed.Connection, nil, idClaims, accessClaims)
	s.emitPendingLogin(claimed.LoginLog, allowed)
	if !allowed {
		return
	}

	idTokenString, err := s.SignToken(idClaims)
	if err != nil {
		http.Error(w, "Token generation failed", 500)
		return
	}

	accessTokenString, err := s.SignToken(accessClaims)
	if err != nil {
		http.Error(w, "Token generation failed", 500)
		return
	}

	// The scope was captured when the code was claimed above.
	var refreshToken string
	if hasScope(requestedScope, "offline_access") {
		refreshToken = s.newRefreshToken()
		s.mu.Lock()
		s.refreshTokens[refreshToken] = &refreshTokenState{
			UserID:         user.ID,
			OrgID:          orgID,
			ClientID:       claimed.ClientID,
			IncludeIDToken: true,
			Audience:       audience,
			Scope:          requestedScope,
			SessionID:      claimed.SessionID,
			Connection:     claimed.Connection,
			Family:         refreshToken,
		}
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

// userInfoURL is the tenant's /userinfo endpoint, which Auth0 also uses as
// an access-token audience.
func (s *Server) userInfoURL() string {
	return strings.TrimSuffix(s.cfg.Issuer, "/") + "/userinfo"
}

// handleUserInfo answers OIDC userinfo as Auth0 does: the profile comes from
// the user store, not the token, filtered by the token's scopes. Only an
// access token whose audience includes /userinfo is accepted, which Auth0
// adds when the login asked for openid.
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Auth0-Client")
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	unauthorized := func() {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}

	tokenString, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tokenString == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (interface{}, error) {
		return &s.privateKey.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithAudience(s.userInfoURL()),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		unauthorized()
		return
	}
	sub, _ := claims.GetSubject()
	user := s.getUserByID(sub)
	if user == nil {
		unauthorized()
		return
	}

	scope, _ := claims["scope"].(string)
	writeOAuthJSON(w, http.StatusOK, userInfoClaims(user, scope))
}

// userInfoClaims are the OIDC standard claims user releases under scope.
// Absent values are omitted, never null.
func userInfoClaims(user *config.User, scope string) map[string]any {
	out := map[string]any{"sub": user.ID}
	if hasScope(scope, "profile") {
		if user.Name != "" {
			out["name"] = user.Name
		}
		if nick := nickname(user); nick != "" {
			out["nickname"] = nick
		}
		if user.Picture != "" {
			out["picture"] = user.Picture
		}
		if user.UpdatedAt != "" {
			out["updated_at"] = user.UpdatedAt
		}
	}
	if hasScope(scope, "email") && user.Email != "" {
		out["email"] = user.Email
		out["email_verified"] = user.EmailVerified
	}
	if hasScope(scope, "phone") && user.Phone != "" {
		out["phone_number"] = user.Phone
		// Matches the ID token: a passwordless sms user is verified unless
		// the store says otherwise.
		out["phone_number_verified"] = user.PhoneVerified == nil || *user.PhoneVerified
	}
	return out
}

// nickname is the default Auth0 gives a passwordless user: the email's local
// part, or the phone number.
func nickname(user *config.User) string {
	if local, _, ok := strings.Cut(user.Email, "@"); ok {
		return local
	}
	return user.Phone
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("returnTo")
	if returnTo == "" {
		returnTo = strings.TrimSuffix(s.cfg.Issuer, "/")
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// defaultScope is the access-token scope when the authorize request named none.
const defaultScope = "openid profile email"

// grantedScope is the access token's scope claim: the scopes the authorize
// request asked for, deduplicated in request order. Auth0 grants the
// requested scopes an API defines; the mock defines no per-API scopes, so it
// grants what was requested rather than a fixed string that drops the API's
// own scopes (for example prayers:write).
func grantedScope(requested string) string {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return defaultScope
	}
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

// idTokenClaims are the ID token claims for user signed in to clientID.
func (s *Server) idTokenClaims(user *config.User, clientID, orgID string, now time.Time) jwt.MapClaims {
	claims := jwt.MapClaims{
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
		claims["phone_number"] = user.Phone
		claims["phone_number_verified"] = true
	}
	if user.Picture != "" {
		claims["picture"] = user.Picture
	}
	nameParts := strings.Split(user.Name, " ")
	claims["given_name"] = nameParts[0]
	if len(nameParts) > 1 {
		claims["family_name"] = nameParts[1]
	}
	s.addOrgClaims(claims, user, orgID)
	return claims
}

// accessAudience is an access token's aud for an API. Auth0 adds its
// /userinfo endpoint when openid is granted, so the one access token also
// reads the profile.
func (s *Server) accessAudience(audience, scope string) any {
	if hasScope(scope, "openid") && audience != s.userInfoURL() {
		return []string{audience, s.userInfoURL()}
	}
	return audience
}

// accessTokenClaims are the claims of user's access token for audience,
// issued to clientID. Auth0 names the client in azp.
func (s *Server) accessTokenClaims(user *config.User, clientID, audience, scope, orgID string, now time.Time) jwt.MapClaims {
	granted := grantedScope(scope)
	claims := jwt.MapClaims{
		"sub":   user.ID,
		"azp":   clientID,
		"iss":   s.cfg.Issuer,
		"aud":   s.accessAudience(audience, granted),
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": granted,
	}
	s.addOrgClaims(claims, user, orgID)
	return claims
}

// addOrgClaims adds the top-level org_id, as Auth0 Organizations does, and
// the namespaced role an Action adds in production.
func (s *Server) addOrgClaims(claims jwt.MapClaims, user *config.User, orgID string) {
	if orgID != "" {
		claims["org_id"] = orgID
	}
	if role := roleForOrg(user, orgID); role != "" {
		claims[strings.TrimSuffix(s.cfg.Issuer, "/")+"/role"] = role
	}
}

// scopeWithin reports whether every scope in requested is in granted.
func scopeWithin(requested []string, granted string) bool {
	have := strings.Fields(granted)
	for _, scope := range requested {
		if !slices.Contains(have, scope) {
			return false
		}
	}
	return true
}

// hasScope reports whether the space-separated scope holds wanted.
func hasScope(scope, wanted string) bool {
	return slices.Contains(strings.Fields(scope), wanted)
}

// writeOAuthJSON writes an OAuth token endpoint body, which must not be cached.
func writeOAuthJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// knownAudience reports whether the tenant has an API with this identifier.
func (s *Server) knownAudience(aud string) bool {
	if aud == s.cfg.Audience {
		return true
	}
	for _, a := range s.cfg.APIs {
		if a.Identifier == aud {
			return true
		}
	}
	return false
}

// authorizeAudience is the API an authorize request asked for, else the default.
func (s *Server) authorizeAudience(rawQuery string) string {
	q, _ := url.ParseQuery(rawQuery)
	if aud := q.Get("audience"); aud != "" && s.knownAudience(aud) {
		return aud
	}
	return s.cfg.Audience
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeOAuthJSON(w, status, map[string]string{"error": code, "error_description": description})
}
