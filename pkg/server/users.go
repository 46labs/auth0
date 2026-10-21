package server

import (
	"cmp"
	"encoding/json"
	"log"
	"maps"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/contact"
)

// handleUsers serves POST /api/v2/users, for passwordless users only:
// enterprise users arrive by signing in.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodPost:
		s.createUser(w, r)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "user listing is not implemented by the auth0 mock")
	}
}

// createUserRequest holds every field the mock stores; others are refused.
type createUserRequest struct {
	Connection    string             `json:"connection"`
	Email         string             `json:"email"`
	PhoneNumber   string             `json:"phone_number"`
	Name          string             `json:"name"`
	EmailVerified *bool              `json:"email_verified"`
	PhoneVerified *bool              `json:"phone_verified"`
	VerifyEmail   *bool              `json:"verify_email"`
	Blocked       *bool              `json:"blocked"`
	AppMetadata   config.AppMetadata `json:"app_metadata"`
	UserMetadata  map[string]any     `json:"user_metadata"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body (fields the auth0 mock does not implement are refused): "+err.Error())
		return
	}
	if req.Connection == "" {
		writeAuth0Error(w, http.StatusBadRequest, "Payload validation error: Missing required property: connection")
		return
	}

	status, msg, user := s.storeNewUser(req)
	if user == nil {
		writeAuth0Error(w, status, msg)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}

// storeNewUser answers a refusal or the stored user, so the caller writes the
// response after the lock is released.
func (s *Server) storeNewUser(req createUserRequest) (int, string, *config.User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn := s.connectionByNameLocked(req.Connection)
	if conn == nil {
		return http.StatusBadRequest, "The connection does not exist.", nil
	}
	if !conn.IsPasswordless() {
		return http.StatusBadRequest, "the auth0 mock creates users only on passwordless connections", nil
	}

	id, now := s.generateID(), auth0Timestamp(time.Now())
	user := &config.User{
		ID:           conn.Strategy + "|" + id,
		Name:         req.Name,
		AppMetadata:  req.AppMetadata,
		UserMetadata: req.UserMetadata,
		Blocked:      req.Blocked,
		CreatedAt:    now,
		UpdatedAt:    now,
		Identities:   []config.UserIdentity{{Connection: conn.Name, Provider: conn.Strategy, UserID: id}},
	}
	switch conn.Strategy {
	case config.StrategyEmail:
		if req.PhoneNumber != "" {
			return http.StatusBadRequest, "Payload validation error: phone_number is only valid for an sms connection", nil
		}
		if !validEmail(req.Email) {
			return http.StatusBadRequest, "Payload validation error: email is required for an email connection", nil
		}
		user.Email = strings.ToLower(req.Email)
	case config.StrategySMS:
		if !e164.MatchString(req.PhoneNumber) {
			return http.StatusBadRequest, "Payload validation error: phone_number must be in E.164 format", nil
		}
		user.Phone = req.PhoneNumber
		if req.Email != "" && !validEmail(req.Email) {
			return http.StatusBadRequest, "Payload validation error: email is not a valid address", nil
		}
		user.Email = strings.ToLower(req.Email)
	}
	user.Name = cmp.Or(user.Name, user.Email, user.Phone)
	if req.EmailVerified != nil {
		user.EmailVerified = *req.EmailVerified
	}
	if req.PhoneVerified != nil {
		if conn.Strategy != config.StrategySMS {
			return http.StatusBadRequest, "Payload validation error: phone_verified is only valid for an sms connection", nil
		}
		v := *req.PhoneVerified
		user.PhoneVerified = &v
	}
	// False until a code proves the number.
	if conn.Strategy == config.StrategySMS && user.PhoneVerified == nil {
		user.PhoneVerified = new(bool)
	}
	if req.VerifyEmail != nil && *req.VerifyEmail {
		log.Printf("verify_email requested for %s; the auth0 mock sends no email", user.Email)
	}
	// Keyed by the identifier the connection sends codes to.
	email, phone := user.Email, ""
	if conn.Strategy == config.StrategySMS {
		email, phone = "", user.Phone
	}
	if s.userInConnectionLocked(conn.Name, email, phone) != nil {
		return http.StatusConflict, "The user already exists.", nil
	}

	s.users[user.ID] = user.Clone()
	return http.StatusCreated, "", user
}

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)

func validEmail(raw string) bool {
	a, err := mail.ParseAddress(raw)
	return err == nil && a.Address == raw
}

// userInConnectionLocked returns the user with an identity in the connection
// for this address. Caller holds the lock.
func (s *Server) userInConnectionLocked(connection, email, phone string) *config.User {
	for _, u := range s.users {
		for i, id := range u.Identities {
			if id.Connection != connection {
				continue
			}
			idEmail, idPhone := identityContact(u, i)
			if (email != "" && strings.EqualFold(idEmail, email)) || (phone != "" && idPhone == phone) {
				return u
			}
		}
	}
	return nil
}

// identityContact is identity i's address: the user's own for the main
// identity, the profile a link carried over for the others.
func identityContact(u *config.User, i int) (email, phone string) {
	if p := u.Identities[i].ProfileData; i > 0 && p != nil {
		email, _ = p["email"].(string)
		phone, _ = p["phone_number"].(string)
		return email, phone
	}
	return u.Email, u.Phone
}

// handleUsersByEmail serves GET /api/v2/users-by-email. The match is exact:
// Auth0 lowercases the addresses it manages on store, not on search.
func (s *Server) handleUsersByEmail(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodGet {
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	email := r.URL.Query().Get("email")
	if email == "" {
		writeAuth0Error(w, http.StatusBadRequest, "Query validation error: Missing required property: email")
		return
	}

	s.mu.RLock()
	out := []*config.User{}
	for _, u := range s.users {
		if u.Email == email {
			out = append(out, u.Clone())
		}
	}
	s.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(out)
}

// handleUserIdentities serves POST /api/v2/users/{id}/identities. Auth0
// deletes the linked user and keeps only the primary's metadata.
func (s *Server) handleUserIdentities(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	primaryID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/users/"), "/identities")
	if primaryID == "" || strings.Contains(primaryID, "/") {
		writeAuth0Error(w, http.StatusNotFound, "route not implemented by the auth0 mock: "+r.URL.Path)
		return
	}

	var req struct {
		Provider     string `json:"provider"`
		UserID       string `json:"user_id"`
		ConnectionID string `json:"connection_id"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body (link_with is not implemented by the auth0 mock): "+err.Error())
		return
	}
	if req.Provider == "" || req.UserID == "" {
		writeAuth0Error(w, http.StatusBadRequest, "Payload validation error: provider and user_id are required")
		return
	}
	// The SDK's own Link test passes the full user id, not the identity's.
	identityID := strings.TrimPrefix(req.UserID, req.Provider+"|")

	status, msg, ids := s.linkUser(primaryID, req.Provider, identityID, req.ConnectionID)
	if ids == nil {
		writeAuth0Error(w, status, msg)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ids)
}

// linkUser answers a refusal or the primary's identities, so the caller writes
// the response after the lock is released.
func (s *Server) linkUser(primaryID, provider, identityID, connectionID string) (int, string, []config.UserIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()

	primary, ok := s.users[primaryID]
	if !ok {
		return http.StatusNotFound, "The user does not exist.", nil
	}
	// By its main identity: a configured user's id need not spell it.
	var secondary *config.User
	for _, u := range s.users {
		if len(u.Identities) > 0 && u.Identities[0].Provider == provider && u.Identities[0].UserID == identityID {
			secondary = u
		}
	}
	if secondary == nil {
		return http.StatusBadRequest, "The user to link does not exist.", nil
	}
	// Index 0 must be the primary's own identity; see identityContact.
	if len(primary.Identities) == 0 {
		return http.StatusBadRequest, "the auth0 mock cannot link into a user with no identities", nil
	}
	if secondary.ID == primaryID {
		return http.StatusBadRequest, "Main identity and the new one are the same.", nil
	}
	secondaryID := secondary.ID
	if connectionID != "" {
		conn, ok := s.connections[connectionID]
		if !ok || len(secondary.Identities) == 0 || secondary.Identities[0].Connection != conn.Name {
			return http.StatusBadRequest, "connection_id does not match the user to link", nil
		}
	}

	// Auth0 puts profileData on every identity; the primary's is refreshed.
	primary.Identities[0].ProfileData = userProfile(primary)
	profile := userProfile(secondary)
	for _, id := range secondary.Identities {
		if id.ProfileData == nil {
			id.ProfileData = profile
		}
		primary.Identities = append(primary.Identities, id)
	}

	delete(s.users, secondaryID)
	s.removeMembershipsLocked(secondaryID)

	return http.StatusCreated, "", primary.Clone().Identities
}

func userProfile(u *config.User) map[string]any {
	p := map[string]any{}
	if u.Email != "" {
		p["email"], p["email_verified"] = u.Email, u.EmailVerified
	}
	if u.Name != "" {
		p["name"] = u.Name
	}
	if u.Phone != "" {
		p["phone_number"] = u.Phone
		p["phone_verified"] = u.PhoneVerified != nil && *u.PhoneVerified
	}
	if u.Picture != "" {
		p["picture"] = u.Picture
	}
	return p
}

// enterpriseUserLocked finds or provisions the connection's user for the
// address, as a first SSO sign-in does. Caller holds the write lock.
func (s *Server) enterpriseUserLocked(conn *config.Connection, email string) *config.User {
	if u := s.userInConnectionLocked(conn.Name, email, ""); u != nil {
		return u
	}
	sub, now := conn.Name+"|"+s.generateID(), auth0Timestamp(time.Now())
	u := &config.User{
		ID: conn.Strategy + "|" + sub,
		// As typed: the IdP, not Auth0, owns its casing.
		Email:         email,
		Name:          email,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
		Identities:    []config.UserIdentity{{Connection: conn.Name, Provider: conn.Strategy, UserID: sub}},
	}
	s.users[u.ID] = u
	return u
}

// loginUser resolves who signs in and the connection actually used, which is
// checked for the client and organization before anyone is provisioned.
func (s *Server) loginUser(identifier, connectionName, clientID, orgID string) (*config.User, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	allow := s.connectionAllowedLocked(clientID, orgID)
	conn := s.connectionByNameLocked(connectionName)
	if connectionName != "" {
		if conn == nil {
			return nil, "", errConnectionUnknown
		}
		if err := allow(conn); err != nil {
			return nil, "", err
		}
	}
	if conn != nil && !conn.IsPasswordless() {
		if contact.IsEmail(identifier) {
			return s.enterpriseUserLocked(conn, identifier).Clone(), conn.Name, nil
		}
		// A directory has no phones; the mock keeps its address lookup.
		u := s.findUserLocked(identifier)
		if u == nil {
			u = s.autoCreateUserLocked(identifier, "")
		}
		return u, conn.Name, nil
	}
	return s.passwordlessUserLocked(identifier, conn, allow)
}

// connectionAllowedLocked checks a sign-in's connection is enabled for the
// client, when registered, and on the organization. Caller holds the lock.
func (s *Server) connectionAllowedLocked(clientID, orgID string) func(*config.Connection) error {
	return func(conn *config.Connection) error {
		if conn == nil {
			return nil
		}
		if _, registered := s.clients[clientID]; registered &&
			!slices.Contains(conn.EnabledClients, "*") && !slices.Contains(conn.EnabledClients, clientID) {
			return errConnectionNotForClient
		}
		if _, ok := s.organizations[orgID]; ok && !s.isConnectionEnabled(orgID, conn.ID) {
			return errConnectionNotInOrg
		}
		return nil
	}
}

func matchesIdentifier(u *config.User, i int, identifier string) bool {
	email, phone := identityContact(u, i)
	return strings.EqualFold(email, identifier) || samePhone(phone, identifier)
}

func samePhone(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	na, errA := contact.NormalizePhoneToE164(a)
	nb, errB := contact.NormalizePhoneToE164(b)
	return errA == nil && errB == nil && na == nb
}

// recordLoginLocked counts a sign-in; a passwordless code also verifies the
// identity it went through. Caller holds the lock.
func (s *Server) recordLoginLocked(userID, identifier, connectionName string) {
	u, ok := s.users[userID]
	if !ok {
		return
	}
	u.LoginsCount++
	now := auth0Timestamp(time.Now())
	u.LastLogin = &now
	if conn := s.connectionByNameLocked(connectionName); conn == nil || !conn.IsPasswordless() {
		return
	}
	for i, id := range u.Identities {
		if id.Connection != connectionName || !matchesIdentifier(u, i, identifier) {
			continue
		}
		key := "email_verified"
		if id.Provider == config.StrategySMS {
			key = "phone_verified"
		}
		switch {
		case i > 0 && id.ProfileData != nil:
			id.ProfileData[key] = true
		case key == "email_verified":
			u.EmailVerified = true
		default:
			verified := true
			u.PhoneVerified = &verified
		}
		return
	}
}

// connectionByNameLocked returns the named connection, or nil. Caller holds
// the lock.
func (s *Server) connectionByNameLocked(name string) *config.Connection {
	for _, c := range s.connections {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// connectionByName is connectionByNameLocked with the read lock taken.
func (s *Server) connectionByName(name string) *config.Connection {
	if name == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connectionByNameLocked(name).Clone()
}

// passwordlessUserLocked resolves a code sign-in, through conn when named,
// checking the connection used with allow first. Caller holds the write lock.
func (s *Server) passwordlessUserLocked(identifier string, conn *config.Connection, allow func(*config.Connection) error) (*config.User, string, error) {
	strategy := config.StrategySMS
	if contact.IsEmail(identifier) {
		strategy = config.StrategyEmail
	}
	// A named connection signs in only its own users and identifier kind.
	connName := ""
	if conn != nil {
		if conn.Strategy != strategy {
			return nil, "", errConnectionWrongIdentifier
		}
		connName = conn.Name
	}
	through := func(u *config.User, name string) (*config.User, string, error) {
		if err := allow(s.connectionByNameLocked(name)); err != nil {
			return nil, "", err
		}
		return u, name, nil
	}
	for _, u := range s.users {
		for i, id := range u.Identities {
			if id.Provider == strategy && (connName == "" || id.Connection == connName) && matchesIdentifier(u, i, identifier) {
				return through(u.Clone(), id.Connection)
			}
		}
	}
	// Otherwise any user with the address answers, as the mock always has;
	// the code still went through the strategy's connection.
	if connName == "" {
		connName = s.passwordlessConnectionNameLocked(strategy)
	}
	if u := s.findUserLocked(identifier); u != nil && (conn == nil || len(u.Identities) == 0) {
		return through(u, connName)
	}
	if err := allow(s.connectionByNameLocked(connName)); err != nil {
		return nil, "", err
	}
	u := s.autoCreateUserLocked(identifier, connName)
	return u, connName, nil
}

// withConnection names the connection signed in through in the login record.
func withConnection(params url.Values, connection string) url.Values {
	if connection == "" || params.Get("connection") == connection {
		return params
	}
	out := maps.Clone(params)
	out.Set("connection", connection)
	return out
}
