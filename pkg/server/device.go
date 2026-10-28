package server

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/contact"
	"github.com/golang-jwt/jwt/v5"
)

const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

const deviceUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// passwordlessCode is the one verification code the mock accepts.
const passwordlessCode = "123456"

func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Auth0-Client")
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method must be POST")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	clientID := clientIDFromRequest(r)
	client := s.lookupClient(clientID)
	if !deviceEligible(client) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client is not eligible for device authorization")
		return
	}

	audience := r.FormValue("audience")
	resource := r.FormValue("resource")
	if audience != "" && resource != "" && audience != resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "audience and resource must match")
		return
	}
	if audience == "" {
		audience = resource
	}
	if audience == "" {
		audience = s.cfg.Audience
	}
	if !s.knownAudience(audience) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "audience is not supported")
		return
	}
	orgID := r.FormValue("organization")
	if orgID != "" {
		s.mu.RLock()
		_, knownOrganization := s.organizations[orgID]
		s.mu.RUnlock()
		if !knownOrganization {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "organization not found")
			return
		}
	}

	scope, err := s.deviceScope(clientID, r.FormValue("scope"), audience)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}

	now := time.Now()
	s.mu.Lock()
	s.pruneDeviceCodesLocked(now)
	deviceCode := s.generateID()
	userCode, err := s.newDeviceUserCodeLocked()
	if err != nil {
		s.mu.Unlock()
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not create device authorization")
		return
	}
	s.deviceCodes[deviceCode] = &deviceTransaction{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Audience:   audience,
		Scope:      scope,
		OrgID:      orgID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.deviceCodeLifetime()),
		Interval:   devicePollInterval,
		Status:     deviceTransactionPending,
	}
	s.mu.Unlock()

	verificationURI := strings.TrimSuffix(s.cfg.Issuer, "/") + "/device"
	displayed := formatDeviceUserCode(userCode)
	writeOAuthJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 displayed,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(displayed),
		"expires_in":                int(s.deviceCodeLifetime() / time.Second),
		"interval":                  int(devicePollInterval / time.Second),
	})
}

func (s *Server) handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	if r.Method == http.MethodGet {
		s.renderDeviceVerification(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method must be GET or POST")
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	userCode := normalizeDeviceUserCode(r.FormValue("user_code"))
	confirmation := normalizeDeviceUserCode(r.FormValue("confirm_user_code"))
	decision := strings.ToLower(r.FormValue("decision"))
	if s.deviceVerificationBlocked(userCode, time.Now()) {
		http.Error(w, "Too many verification attempts", http.StatusTooManyRequests)
		return
	}
	if userCode == "" || confirmation != userCode || (decision != "approve" && decision != "deny") {
		s.reportDeviceVerificationFailure(userCode, time.Now())
		http.Error(w, "The displayed user code must be confirmed", http.StatusBadRequest)
		return
	}
	identifier := r.FormValue("identifier")
	now := time.Now()
	s.mu.Lock()
	s.pruneDeviceCodesLocked(now)
	transaction := s.deviceTransactionByUserCodeLocked(userCode)
	var clientID, orgID string
	expired, busy, eligible := false, false, false
	if transaction != nil {
		clientID, orgID = transaction.ClientID, transaction.OrgID
		expired = !now.Before(transaction.ExpiresAt)
		busy = transaction.Status != deviceTransactionPending || transaction.Verifying
		eligible = deviceEligible(s.clients[clientID])
		// Reserved until this post decides, so a concurrent one is refused
		// before it can sign anyone in.
		if !expired && !busy && eligible {
			transaction.Verifying = true
		}
	}
	s.mu.Unlock()
	params := url.Values{"client_id": {clientID}}
	if orgID != "" {
		params.Set("organization", orgID)
	}
	// The request's state is settled before anything signs in, so a stale or
	// spent user code provisions no one.
	switch {
	case transaction == nil:
		s.emitLoginLog(r, params, "fdeac", "Invalid or expired user code", nil, identifier, "")
		http.Error(w, "Invalid or expired user code", http.StatusBadRequest)
		return
	case expired:
		s.emitLoginLog(r, params, "fdeac", "This device authorization has expired", nil, identifier, orgID)
		http.Error(w, "This device authorization has expired", http.StatusBadRequest)
		return
	case busy:
		http.Error(w, "This device authorization is no longer pending", http.StatusConflict)
		return
	case !eligible:
		s.emitLoginLog(r, params, "fdeac", "The application can no longer authorize devices", nil, identifier, orgID)
		http.Error(w, "The application can no longer authorize devices", http.StatusBadRequest)
		return
	}
	defer func() {
		s.mu.Lock()
		transaction.Verifying = false
		s.mu.Unlock()
	}()
	if !validIdentifier(identifier) {
		s.reportDeviceVerificationFailure(userCode, now)
		s.emitLoginLog(r, params, "f", "Invalid email or phone number.", nil, identifier, orgID)
		http.Error(w, "Invalid email or phone number", http.StatusBadRequest)
		return
	}

	if r.FormValue("code") != passwordlessCode {
		s.reportDeviceVerificationFailure(userCode, now)
		s.emitLoginLog(r, params, "f", "Wrong email or verification code.", s.findUser(identifier), identifier, orgID)
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}
	user, connection, err := s.loginUser(identifier, "", clientID, orgID)
	if err != nil {
		s.reportDeviceVerificationFailure(userCode, now)
		s.emitLoginLog(r, params, "f", err.Error(), nil, identifier, orgID)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	params = withConnection(params, connection)
	// Only approval needs membership: anyone shown the request may refuse it.
	if decision == "approve" && orgID != "" {
		if err := s.authorizeOrgLogin(user, orgID, ""); err != nil {
			s.emitLoginLog(r, params, "f", err.Error(), user, identifier, orgID)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	// The success record is held until the token exchange, where the
	// post-login Action decides it, as the authorization code flow does.
	var loginLog map[string]any
	if decision == "approve" {
		loginLog = s.loginLog(r, params, "s", "Successful login", user, identifier, orgID)
	}

	s.mu.Lock()
	// Signing in took time: the request may have expired meanwhile, and a
	// poll may have marked it so.
	if !time.Now().Before(transaction.ExpiresAt) || transaction.Status != deviceTransactionPending {
		transaction.Status = deviceTransactionExpired
		s.mu.Unlock()
		s.emitLoginLog(r, params, "fdeac", "This device authorization has expired", user, identifier, orgID)
		http.Error(w, "This device authorization has expired", http.StatusBadRequest)
		return
	}
	if decision == "approve" {
		s.recordLoginLocked(user.ID, identifier, connection)
		transaction.ApprovedBy = user.ID
		transaction.Connection = connection
		transaction.LoginLog = loginLog
		transaction.Status = deviceTransactionApproved
	} else {
		transaction.Status = deviceTransactionDenied
	}
	transaction.FailedAttempts = 0
	transaction.BlockedUntil = time.Time{}
	s.mu.Unlock()

	message := "Device authorization approved. You can return to the device."
	if decision != "approve" {
		s.emitLoginLog(r, params, "fdecc", "User did not confirm device", user, identifier, orgID)
		message = "Device authorization denied."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.templates.ExecuteDevice(w, map[string]any{
		"Branding": s.cfg.Branding,
		"Message":  message,
	})
}

func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request, clientID string) {
	deviceCode := r.FormValue("device_code")
	if deviceCode == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "device_code and client_id are required")
		return
	}

	client := s.lookupClient(clientID)
	if !deviceEligible(client) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client is not eligible for device authorization")
		return
	}

	now := time.Now()
	s.mu.Lock()
	s.pruneDeviceCodesLocked(now)
	transaction, exists := s.deviceCodes[deviceCode]
	if !exists || transaction.ClientID != clientID {
		s.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid device code")
		return
	}
	if transaction.Status == deviceTransactionConsumed || transaction.Status == deviceTransactionExpired {
		s.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid device code")
		return
	}
	if !s.knownAudience(transaction.Audience) {
		s.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "device code is no longer valid")
		return
	}
	if !now.Before(transaction.ExpiresAt) {
		transaction.Status = deviceTransactionExpired
		s.mu.Unlock()
		writeOAuthError(w, http.StatusForbidden, "expired_token", "device code has expired")
		return
	}
	if transaction.Status == deviceTransactionDenied {
		s.mu.Unlock()
		writeOAuthError(w, http.StatusForbidden, "access_denied", "the user denied the request")
		return
	}
	if !transaction.NextPollAt.IsZero() && now.Before(transaction.NextPollAt) {
		transaction.Interval += 5 * time.Second
		transaction.NextPollAt = now.Add(transaction.Interval)
		s.mu.Unlock()
		writeOAuthError(w, http.StatusTooManyRequests, "slow_down", "polling too frequently")
		return
	}
	if transaction.Status == deviceTransactionPending {
		transaction.NextPollAt = now.Add(transaction.Interval)
		s.mu.Unlock()
		writeOAuthError(w, http.StatusForbidden, "authorization_pending", "authorization is pending")
		return
	}

	user := s.users[transaction.ApprovedBy]
	if user == nil {
		transaction.Status = deviceTransactionConsumed
		s.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "user no longer exists")
		return
	}
	userCopy := user.Clone()
	orgID := transaction.OrgID
	if orgID == "" {
		orgID = userCopy.AppMetadata.TenantID()
	}
	scope := transaction.Scope
	connection, loginLog := transaction.Connection, transaction.LoginLog
	transaction.Status = deviceTransactionConsumed
	s.mu.Unlock()

	if seeded := s.seedOrgRoles(userCopy.ID, orgID); seeded != nil {
		userCopy = seeded
	} else if latest := s.getUserByID(userCopy.ID); latest != nil {
		userCopy = latest
	}

	idClaims := jwt.MapClaims{}
	if hasScope(scope, "openid") {
		idClaims = s.idTokenClaims(userCopy, clientID, orgID, now)
		idClaims["auth_time"] = now.Unix()
	}
	accessClaims := s.accessTokenClaims(userCopy, transaction.Audience, scope, orgID, now)
	// The approval is a login, so it starts a session that every token
	// refreshed from it keeps, as with the authorization code flow.
	sessionID := "sess_" + s.generateID()
	if hasScope(scope, "openid") {
		idClaims["sid"] = sessionID
	}
	allowed := s.postLogin(w, r, userCopy, clientID, orgID, "", "oauth2-device-code", sessionID, connection, strings.Fields(scope), idClaims, accessClaims)
	s.emitPendingLogin(loginLog, allowed)
	if !allowed {
		return
	}

	accessTokenString, err := s.SignToken(accessClaims)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"access_token": accessTokenString,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        grantedScope(scope),
	}
	if hasScope(scope, "openid") {
		idTokenString, err := s.SignToken(idClaims)
		if err != nil {
			http.Error(w, "Token generation failed", http.StatusInternalServerError)
			return
		}
		response["id_token"] = idTokenString
	}
	if hasScope(scope, "offline_access") {
		refreshToken := s.newRefreshToken()
		s.mu.Lock()
		s.refreshTokens[refreshToken] = &refreshTokenState{
			UserID:         userCopy.ID,
			OrgID:          orgID,
			ClientID:       clientID,
			IncludeIDToken: hasScope(scope, "openid"),
			Audience:       transaction.Audience,
			Scope:          scope,
			SessionID:      sessionID,
			Connection:     connection,
			Family:         refreshToken,
		}
		s.mu.Unlock()
		response["refresh_token"] = refreshToken
	}

	writeOAuthJSON(w, http.StatusOK, response)
}

func (s *Server) renderDeviceVerification(w http.ResponseWriter, r *http.Request) {
	userCode := normalizeDeviceUserCode(r.URL.Query().Get("user_code"))
	if userCode == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = s.templates.ExecuteDevice(w, map[string]any{
			"Branding": s.cfg.Branding,
		})
		return
	}

	now := time.Now()
	s.mu.Lock()
	s.pruneDeviceCodesLocked(now)
	transaction := s.deviceTransactionByUserCodeLocked(userCode)
	if transaction == nil {
		s.mu.Unlock()
		http.Error(w, "Invalid or expired user code", http.StatusBadRequest)
		return
	}
	if !now.Before(transaction.ExpiresAt) {
		transaction.Status = deviceTransactionExpired
		s.mu.Unlock()
		http.Error(w, "This device authorization has expired", http.StatusBadRequest)
		return
	}
	if transaction.Status != deviceTransactionPending {
		s.mu.Unlock()
		http.Error(w, "This device authorization is no longer pending", http.StatusConflict)
		return
	}
	clientName := transaction.ClientID
	if client := s.clients[transaction.ClientID]; client != nil && client.Name != "" {
		clientName = client.Name
	}
	page := map[string]any{
		"Branding":   s.cfg.Branding,
		"UserCode":   formatDeviceUserCode(transaction.UserCode),
		"ClientName": clientName,
		"Audience":   transaction.Audience,
		"Scope":      transaction.Scope,
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.templates.ExecuteDevice(w, page)
}

func (s *Server) deviceScope(clientID, requested, audience string) (string, error) {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return defaultScope, nil
	}

	allowed := map[string]bool{
		"openid":         true,
		"profile":        true,
		"email":          true,
		"phone":          true,
		"offline_access": true,
	}
	s.mu.RLock()
	for _, grant := range s.clientGrants {
		if grant.ClientID != clientID || grant.Audience != audience {
			continue
		}
		for _, scope := range grant.Scope {
			allowed[scope] = true
		}
	}
	s.mu.RUnlock()

	seen := make(map[string]bool, len(fields))
	normalized := make([]string, 0, len(fields))
	for _, scope := range fields {
		if !allowed[scope] {
			return "", fmt.Errorf("scope %q is not authorized for this client", scope)
		}
		if !seen[scope] {
			seen[scope] = true
			normalized = append(normalized, scope)
		}
	}
	return strings.Join(normalized, " "), nil
}

// deviceEligible reports whether client may use the device flow: a native
// application allowed the grant.
func deviceEligible(client *config.Client) bool {
	return client != nil && client.AppType == "native" && slices.Contains(client.GrantTypes, deviceCodeGrantType)
}

func (s *Server) newDeviceUserCodeLocked() (string, error) {
	for range 10 {
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		var builder strings.Builder
		for _, b := range bytes {
			builder.WriteByte(deviceUserCodeAlphabet[int(b)%len(deviceUserCodeAlphabet)])
		}
		candidate := builder.String()
		if s.deviceTransactionByUserCodeLocked(candidate) == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("user code collision")
}

func (s *Server) deviceTransactionByUserCodeLocked(userCode string) *deviceTransaction {
	for _, transaction := range s.deviceCodes {
		if transaction.UserCode == userCode {
			return transaction
		}
	}
	return nil
}

func (s *Server) deviceCodeLifetime() time.Duration {
	if s.cfg.DeviceCodeLifetime > 0 {
		return s.cfg.DeviceCodeLifetime
	}
	return defaultDeviceCodeLifetime
}

func (s *Server) pruneDeviceCodesLocked(now time.Time) {
	for deviceCode, transaction := range s.deviceCodes {
		if now.After(transaction.ExpiresAt.Add(s.deviceCodeLifetime())) {
			delete(s.deviceCodes, deviceCode)
		}
	}
}

func (s *Server) deviceVerificationBlocked(userCode string, now time.Time) bool {
	if userCode == "" {
		return false
	}
	s.mu.RLock()
	transaction := s.deviceTransactionByUserCodeLocked(userCode)
	blocked := transaction != nil && now.Before(transaction.BlockedUntil)
	s.mu.RUnlock()
	return blocked
}

func (s *Server) reportDeviceVerificationFailure(userCode string, now time.Time) {
	if userCode == "" {
		return
	}
	s.mu.Lock()
	transaction := s.deviceTransactionByUserCodeLocked(userCode)
	if transaction != nil {
		transaction.FailedAttempts++
		if transaction.FailedAttempts >= 5 {
			transaction.BlockedUntil = now.Add(time.Minute)
		}
	}
	s.mu.Unlock()
}

// validIdentifier reports whether identifier is an email address or a phone
// number, the two a passwordless sign-in takes.
func validIdentifier(identifier string) bool {
	// Classified as loginUser classifies it.
	if contact.IsEmail(identifier) {
		addr, err := mail.ParseAddress(identifier)
		return err == nil && addr.Address == identifier
	}
	_, err := contact.NormalizePhoneToE164(identifier)
	return err == nil
}

func normalizeDeviceUserCode(value string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(value))
}

func formatDeviceUserCode(value string) string {
	value = normalizeDeviceUserCode(value)
	if len(value) != 8 {
		return value
	}
	return value[:4] + "-" + value[4:]
}
