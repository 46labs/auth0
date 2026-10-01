package server

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

const deviceUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Auth0-Client")
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		writeDeviceError(w, http.StatusMethodNotAllowed, "invalid_request", "method must be POST")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	clientID := clientIDFromRequest(r)
	client := s.lookupClient(clientID)
	if client == nil || client.AppType != "native" || !hasGrantType(client, deviceCodeGrantType) {
		writeDeviceError(w, http.StatusUnauthorized, "invalid_client", "client is not eligible for device authorization")
		return
	}

	audience := r.FormValue("audience")
	resource := r.FormValue("resource")
	if audience != "" && resource != "" && audience != resource {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "audience and resource must match")
		return
	}
	if audience == "" {
		audience = resource
	}
	if audience == "" {
		audience = s.cfg.Audience
	}
	if audience != s.cfg.Audience {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "audience is not supported")
		return
	}
	orgID := r.FormValue("organization")
	if orgID != "" {
		s.mu.RLock()
		_, knownOrganization := s.organizations[orgID]
		s.mu.RUnlock()
		if !knownOrganization {
			writeDeviceError(w, http.StatusBadRequest, "invalid_request", "organization not found")
			return
		}
	}

	scope, err := s.deviceScope(clientID, r.FormValue("scope"), audience)
	if err != nil {
		writeDeviceError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}

	now := time.Now()
	s.mu.Lock()
	s.pruneDeviceCodesLocked(now)
	deviceCode := s.generateID()
	userCode, err := s.newDeviceUserCodeLocked()
	if err != nil {
		s.mu.Unlock()
		writeDeviceError(w, http.StatusInternalServerError, "server_error", "could not create device authorization")
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code":               deviceCode,
		"user_code":                 formatDeviceUserCode(userCode),
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(formatDeviceUserCode(userCode)),
		"expires_in":                int(s.deviceCodeLifetime() / time.Second),
		"interval":                  int(devicePollInterval / time.Second),
	})
}

func (s *Server) handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	if r.Method == http.MethodGet {
		s.renderDeviceVerification(w, r, "")
		return
	}
	if r.Method != http.MethodPost {
		writeDeviceError(w, http.StatusMethodNotAllowed, "invalid_request", "method must be GET or POST")
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
	if r.FormValue("code") != "123456" {
		s.reportDeviceVerificationFailure(userCode, time.Now())
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	user := s.findUser(r.FormValue("identifier"))
	if user == nil {
		s.reportDeviceVerificationFailure(userCode, time.Now())
		http.Error(w, "Unknown user", http.StatusBadRequest)
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
	if transaction.OrgID != "" {
		if err := s.authorizeOrgLoginLocked(user, transaction.OrgID, ""); err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if decision == "approve" {
		transaction.ApprovedBy = user.ID
		transaction.Status = deviceTransactionApproved
	} else {
		transaction.Status = deviceTransactionDenied
	}
	transaction.FailedAttempts = 0
	transaction.BlockedUntil = time.Time{}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	message := "Device authorization denied."
	if decision == "approve" {
		message = "Device authorization approved. You can return to the device."
	}
	_ = s.templates.ExecuteDevice(w, map[string]any{
		"Branding": s.cfg.Branding,
		"Message":  message,
	})
}

func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request, clientID string) {
	deviceCode := r.FormValue("device_code")
	if deviceCode == "" || clientID == "" {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "device_code and client_id are required")
		return
	}

	client := s.lookupClient(clientID)
	if client == nil || client.AppType != "native" || !hasGrantType(client, deviceCodeGrantType) {
		writeDeviceError(w, http.StatusUnauthorized, "invalid_client", "client is not eligible for device authorization")
		return
	}

	now := time.Now()
	s.mu.Lock()
	s.pruneDeviceCodesLocked(now)
	transaction, exists := s.deviceCodes[deviceCode]
	if !exists || transaction.ClientID != clientID {
		s.mu.Unlock()
		writeDeviceError(w, http.StatusBadRequest, "invalid_grant", "invalid device code")
		return
	}
	if transaction.Status == deviceTransactionConsumed || transaction.Status == deviceTransactionExpired {
		s.mu.Unlock()
		writeDeviceError(w, http.StatusBadRequest, "invalid_grant", "invalid device code")
		return
	}
	if transaction.Audience != s.cfg.Audience {
		s.mu.Unlock()
		writeDeviceError(w, http.StatusBadRequest, "invalid_grant", "device code is no longer valid")
		return
	}
	if !now.Before(transaction.ExpiresAt) {
		transaction.Status = deviceTransactionExpired
		s.mu.Unlock()
		writeDeviceError(w, http.StatusForbidden, "expired_token", "device code has expired")
		return
	}
	if transaction.Status == deviceTransactionDenied {
		s.mu.Unlock()
		writeDeviceError(w, http.StatusForbidden, "access_denied", "the user denied the request")
		return
	}
	if !transaction.NextPollAt.IsZero() && now.Before(transaction.NextPollAt) {
		transaction.Interval += 5 * time.Second
		transaction.NextPollAt = now.Add(transaction.Interval)
		s.mu.Unlock()
		writeDeviceError(w, http.StatusTooManyRequests, "slow_down", "polling too frequently")
		return
	}
	if transaction.Status == deviceTransactionPending {
		transaction.NextPollAt = now.Add(transaction.Interval)
		s.mu.Unlock()
		writeDeviceError(w, http.StatusForbidden, "authorization_pending", "authorization is pending")
		return
	}

	user := s.users[transaction.ApprovedBy]
	if user == nil {
		transaction.Status = deviceTransactionConsumed
		s.mu.Unlock()
		writeDeviceError(w, http.StatusBadRequest, "invalid_grant", "user no longer exists")
		return
	}
	userCopy := user.Clone()
	orgID := transaction.OrgID
	if orgID == "" {
		orgID = userCopy.AppMetadata.TenantID()
	}
	scope := transaction.Scope
	transaction.Status = deviceTransactionConsumed
	s.mu.Unlock()

	if seeded := s.seedOrgRoles(userCopy.ID, orgID); seeded != nil {
		userCopy = seeded
	} else if latest := s.getUserByID(userCopy.ID); latest != nil {
		userCopy = latest
	}

	ns := strings.TrimSuffix(s.cfg.Issuer, "/") + "/"
	idClaims := jwt.MapClaims{}
	if hasDeviceScope(scope, "openid") {
		idClaims = jwt.MapClaims{
			"sub":            userCopy.ID,
			"email":          userCopy.Email,
			"email_verified": userCopy.EmailVerified,
			"name":           userCopy.Name,
			"iss":            s.cfg.Issuer,
			"aud":            clientID,
			"exp":            now.Add(time.Hour).Unix(),
			"iat":            now.Unix(),
			"auth_time":      now.Unix(),
		}
		if userCopy.Phone != "" {
			idClaims["phone_number"] = userCopy.Phone
			idClaims["phone_number_verified"] = true
		}
		if userCopy.Picture != "" {
			idClaims["picture"] = userCopy.Picture
		}
		nameParts := strings.Split(userCopy.Name, " ")
		if len(nameParts) > 0 {
			idClaims["given_name"] = nameParts[0]
		}
		if len(nameParts) > 1 {
			idClaims["family_name"] = nameParts[1]
		}
		if orgID != "" {
			idClaims["org_id"] = orgID
		}
		if role := roleForOrg(userCopy, orgID); role != "" {
			idClaims[ns+"role"] = role
		}
	}

	accessClaims := jwt.MapClaims{
		"sub":   userCopy.ID,
		"iss":   s.cfg.Issuer,
		"aud":   transaction.Audience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": grantedScope(scope),
	}
	if orgID != "" {
		accessClaims["org_id"] = orgID
	}
	if role := roleForOrg(userCopy, orgID); role != "" {
		accessClaims[ns+"role"] = role
	}
	// The approval is a login, so it starts a session that every token
	// refreshed from it keeps, as with the authorization code flow.
	sessionID := "sess_" + s.generateID()
	if hasDeviceScope(scope, "openid") {
		idClaims["sid"] = sessionID
	}
	if !s.postLogin(w, r, userCopy, clientID, orgID, "", "oauth2-device-code", sessionID, strings.Fields(scope), idClaims, accessClaims) {
		return
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = "key-1"
	accessTokenString, err := accessToken.SignedString(s.privateKey)
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
	if hasDeviceScope(scope, "openid") {
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
		idToken.Header["kid"] = "key-1"
		idTokenString, err := idToken.SignedString(s.privateKey)
		if err != nil {
			http.Error(w, "Token generation failed", http.StatusInternalServerError)
			return
		}
		response["id_token"] = idTokenString
	}
	if hasDeviceScope(scope, "offline_access") {
		refreshToken := "rt_" + s.generateID()
		s.mu.Lock()
		s.refreshTokens[refreshToken] = &refreshTokenState{
			UserID:         userCopy.ID,
			OrgID:          orgID,
			ClientID:       clientID,
			IncludeIDToken: hasDeviceScope(scope, "openid"),
			Scope:          scope,
			SessionID:      sessionID,
		}
		s.mu.Unlock()
		response["refresh_token"] = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(response)
}

func hasDeviceScope(scope, wanted string) bool {
	for _, candidate := range strings.Fields(scope) {
		if candidate == wanted {
			return true
		}
	}
	return false
}

func (s *Server) renderDeviceVerification(w http.ResponseWriter, r *http.Request, message string) {
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
		"Message":    message,
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

func hasGrantType(client *config.Client, grantType string) bool {
	for _, candidate := range client.GrantTypes {
		if candidate == grantType {
			return true
		}
	}
	return false
}

func writeDeviceError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
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
