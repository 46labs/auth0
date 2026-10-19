package server

import (
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

// handleUsers serves POST /api/v2/users. Only passwordless users can be
// created: the mock has no database connections and enterprise users arrive
// by signing in.
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

// createUserRequest holds every field the mock can store. Anything else is
// refused rather than dropped.
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

// storeNewUser validates and stores a created user, answering the status and
// message of a refusal, or the stored user's copy. The response is written
// after the lock is released.
func (s *Server) storeNewUser(req createUserRequest) (int, string, *config.User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var conn *config.Connection
	for _, c := range s.connections {
		if c.Name == req.Connection {
			conn = c
		}
	}
	if conn == nil {
		return http.StatusBadRequest, "The connection does not exist.", nil
	}
	if !conn.IsPasswordless() {
		return http.StatusBadRequest, "the auth0 mock creates users only on passwordless connections", nil
	}

	id := s.generateID()
	user := &config.User{
		ID:           conn.Strategy + "|" + id,
		Name:         req.Name,
		AppMetadata:  req.AppMetadata,
		UserMetadata: req.UserMetadata,
		Blocked:      req.Blocked,
		Identities:   []config.UserIdentity{{Connection: conn.Name, Provider: conn.Strategy, UserID: id}},
	}
	user.CreatedAt = auth0Timestamp(time.Now())
	user.UpdatedAt = user.CreatedAt
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
	if user.Name == "" {
		user.Name = firstNonEmpty(user.Email, user.Phone)
	}
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
	// An sms user always reports phone_verified, false until a code proves it.
	if conn.Strategy == config.StrategySMS && user.PhoneVerified == nil {
		user.PhoneVerified = new(bool)
	}
	if req.VerifyEmail != nil && *req.VerifyEmail {
		// The mock never sends email; accepted and logged, as invitations are.
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

// e164 is the phone format Auth0 requires on user creation.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)

// validEmail reports a bare address, as Auth0's payload validation requires.
func validEmail(raw string) bool {
	a, err := mail.ParseAddress(raw)
	return err == nil && a.Address == raw
}

// userInConnectionLocked returns the user holding an identity in the named
// connection for this address, including one a link carried over. Caller
// holds the lock.
func (s *Server) userInConnectionLocked(connection, email, phone string) *config.User {
	for _, u := range s.users {
		for i, id := range u.Identities {
			if id.Connection != connection {
				continue
			}
			// The main identity is the user's live profile; a linked one
			// keeps the profile it carried over.
			uEmail, uPhone := u.Email, u.Phone
			if i > 0 && id.ProfileData != nil {
				uEmail, _ = id.ProfileData["email"].(string)
				uPhone, _ = id.ProfileData["phone_number"].(string)
			}
			if (email != "" && strings.EqualFold(uEmail, email)) || (phone != "" && uPhone == phone) {
				return u
			}
		}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// handleUsersByEmail serves GET /api/v2/users-by-email: every user with the
// address, as a bare array. The match is exact, as Auth0's is: it lowercases
// the addresses it manages when storing them, not when searching.
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

// handleUserIdentities serves POST /api/v2/users/{id}/identities: link the
// user named by provider and user_id into the primary. Auth0 deletes the
// secondary user and keeps only the primary's metadata.
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
	// Both the identity's own id and the full user id name the user to link,
	// as the SDK's own Link test passes the latter.
	identityID := strings.TrimPrefix(req.UserID, req.Provider+"|")

	status, msg, ids := s.linkUser(primaryID, req.Provider, identityID, req.ConnectionID)
	if ids == nil {
		writeAuth0Error(w, status, msg)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ids)
}

// linkUser moves the secondary's identities onto the primary and deletes the
// secondary, answering a refusal or the primary's identities. The response is
// written after the lock is released.
func (s *Server) linkUser(primaryID, provider, identityID, connectionID string) (int, string, []config.UserIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()

	primary, ok := s.users[primaryID]
	if !ok {
		return http.StatusNotFound, "The user does not exist.", nil
	}
	// Found by its main identity, which a configured user's id need not spell.
	var secondary *config.User
	for _, u := range s.users {
		if len(u.Identities) > 0 && u.Identities[0].Provider == provider && u.Identities[0].UserID == identityID {
			secondary = u
		}
	}
	if secondary == nil {
		return http.StatusBadRequest, "The user to link does not exist.", nil
	}
	// Linking needs the primary's own identity at index 0, which the lookups
	// read as its live profile.
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

	profile := userProfile(secondary)
	// Auth0 answers with profileData on every identity, the primary's own too.
	// The main identity's is rebuilt each time, so a profile change since
	// the last link shows.
	if len(primary.Identities) > 0 {
		primary.Identities[0].ProfileData = userProfile(primary)
	}
	for _, id := range secondary.Identities {
		if id.ProfileData == nil {
			id.ProfileData = profile
		}
		primary.Identities = append(primary.Identities, id)
	}

	delete(s.users, secondaryID)
	for orgID, ms := range s.members {
		kept := ms[:0]
		for _, m := range ms {
			if m.UserID != secondaryID {
				kept = append(kept, m)
			}
		}
		s.members[orgID] = kept
	}

	return http.StatusCreated, "", primary.Clone().Identities
}

// userProfile is the profileData Auth0 records for a linked identity.
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

// enterpriseUserLocked returns the user federated through the enterprise
// connection for the address, provisioning it as Auth0 does on a first SSO
// sign-in. Caller holds the write lock.
func (s *Server) enterpriseUserLocked(conn *config.Connection, email string) *config.User {
	if u := s.userInConnectionLocked(conn.Name, email, ""); u != nil {
		return u
	}
	sub := conn.Name + "|" + s.generateID()
	u := &config.User{
		ID: conn.Strategy + "|" + sub,
		// Kept as typed: an enterprise IdP, not Auth0, owns its casing.
		Email:         email,
		Name:          email,
		EmailVerified: true,
		Identities:    []config.UserIdentity{{Connection: conn.Name, Provider: conn.Strategy, UserID: sub}},
	}
	u.CreatedAt = auth0Timestamp(time.Now())
	u.UpdatedAt = u.CreatedAt
	s.users[u.ID] = u
	return u
}

// loginUser resolves who signs in with identifier through the named
// connection, and the connection the sign-in went through. A passwordless or
// unnamed connection prefers the user holding a passwordless identity for the
// address, so a linked user signs in as its primary. An enterprise connection
// finds or provisions the user federated through it, as Auth0 does on a first
// SSO sign-in; a phone number there falls back to the address lookup, since an
// enterprise directory has none. The connection actually used is checked for
// clientID and orgID before anyone is found or provisioned, under the same
// lock.
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
		// A phone through an enterprise connection keeps the mock's address
		// lookup; the named connection is the one checked and reported.
		u := s.findUserLocked(identifier)
		if u == nil {
			u = s.autoCreateUserLocked(identifier, "")
		}
		return u, conn.Name, nil
	}
	return s.passwordlessUserLocked(identifier, conn, allow)
}

// connectionAllowedLocked returns the check Auth0 applies to the connection a
// sign-in uses: enabled for the calling client, when that client is
// registered, and enabled on the organization, when one is named and exists.
// Caller holds the lock.
func (s *Server) connectionAllowedLocked(clientID, orgID string) func(*config.Connection) error {
	return func(conn *config.Connection) error {
		if conn == nil {
			return nil
		}
		// The mock serves unregistered client ids, which have no enablement.
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

// matchesIdentifier reports whether the user's identity i belongs to the
// address: the user's own for the main identity, else the profile a link
// carried over.
func matchesIdentifier(u *config.User, i int, identifier string) bool {
	if id := u.Identities[i]; i > 0 && id.ProfileData != nil {
		email, _ := id.ProfileData["email"].(string)
		phone, _ := id.ProfileData["phone_number"].(string)
		return strings.EqualFold(email, identifier) || samePhone(phone, identifier)
	}
	return strings.EqualFold(u.Email, identifier) || samePhone(u.Phone, identifier)
}

func samePhone(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	na, errA := contact.NormalizePhoneToE164(a)
	nb, errB := contact.NormalizePhoneToE164(b)
	return errA == nil && errB == nil && na == nb
}

// recordLoginLocked counts a successful sign-in through the named connection.
// A passwordless code proves the address: the user's own when it is the user's
// main identity, else the linked identity's profile. Caller holds the lock.
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
		if id.Connection != connectionName {
			continue
		}
		switch {
		case i > 0 && id.ProfileData != nil:
			if id.Provider == config.StrategyEmail {
				if email, _ := id.ProfileData["email"].(string); strings.EqualFold(email, identifier) {
					id.ProfileData["email_verified"] = true
					return
				}
			} else if phone, _ := id.ProfileData["phone_number"].(string); id.Provider == config.StrategySMS && samePhone(phone, identifier) {
				id.ProfileData["phone_verified"] = true
				return
			}
		case id.Provider == config.StrategyEmail && strings.EqualFold(u.Email, identifier):
			u.EmailVerified = true
			return
		case id.Provider == config.StrategySMS && samePhone(u.Phone, identifier):
			verified := true
			u.PhoneVerified = &verified
			return
		}
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

// passwordlessUserLocked resolves a passwordless sign-in for identifier,
// through conn when one is named, and the connection it went through. The
// connection each candidate signs in through passes allow before the user is
// returned or provisioned. Caller holds the write lock.
func (s *Server) passwordlessUserLocked(identifier string, conn *config.Connection, allow func(*config.Connection) error) (*config.User, string, error) {
	strategy := config.StrategySMS
	if contact.IsEmail(identifier) {
		strategy = config.StrategyEmail
	}
	// A named passwordless connection signs in only its own users, and only
	// with the kind of identifier it sends codes to.
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
	// Without a connection, any user with the address answers, as the mock
	// always has. A configured user that lists no identities has no
	// provenance to rule it out, so it answers a named connection too.
	// Either way the code went through the passwordless connection for the
	// identifier's strategy, so that is the one checked and reported.
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

// withConnection returns params naming the connection signed in through, so
// the login record names it rather than the user's first matching identity.
func withConnection(params url.Values, connection string) url.Values {
	if connection == "" || params.Get("connection") == connection {
		return params
	}
	out := maps.Clone(params)
	out.Set("connection", connection)
	return out
}
