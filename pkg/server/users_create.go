package server

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
)

// Strategies POST /api/v2/users accepts. Auth0 creates users only in
// connections it owns the credentials for; an enterprise or social connection
// is federated, so there is no user for Auth0 to create and it answers 400.
// Database (`auth0`) is deliberately absent: it requires a password and uses a
// provider-prefixed `auth0|` subject, neither of which this implements, and
// answering 201 without them is the false success AGENTS.md warns about.
// e164Pattern is the form Auth0 requires of phone_number on create.
var e164Pattern = regexp.MustCompile(`^\+[0-9]{1,15}$`)

var createUserStrategies = map[string]bool{
	"email": true, // passwordless
	"sms":   true, // passwordless
}

// handleUsersCollection serves the bare /api/v2/users collection. The existing
// "/api/v2/users/" pattern only matches sub-paths, so a POST to the collection
// reached no handler at all.
func (s *Server) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodPost:
		s.createUser(w, r)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// createUserRequest is the subset of management.User this accepts. Fields the
// SDK can send are listed so they are stored rather than silently dropped: a
// 201 that loses what the caller sent is the false success AGENTS.md warns
// about.
type createUserRequest struct {
	// ID is the SDK's `user_id` create attribute, which its marshaler sends
	// whenever the caller set management.User.ID.
	ID            string                 `json:"user_id"`
	Email         string                 `json:"email"`
	Phone         string                 `json:"phone_number"`
	Connection    string                 `json:"connection"`
	Name          string                 `json:"name"`
	GivenName     string                 `json:"given_name"`
	FamilyName    string                 `json:"family_name"`
	Nickname      string                 `json:"nickname"`
	Username      string                 `json:"username"`
	Picture       string                 `json:"picture"`
	EmailVerified bool                   `json:"email_verified"`
	PhoneVerified *bool                  `json:"phone_verified"`
	Blocked       *bool                  `json:"blocked"`
	AppMetadata   config.AppMetadata     `json:"app_metadata"`
	UserMetadata  map[string]interface{} `json:"user_metadata"`
	// VerifyEmail asks Auth0 to send a verification mail. Accepted and ignored
	// because the mock sends none; modelled so a caller that sets it is not
	// refused by the strict decode above.
	VerifyEmail *bool `json:"verify_email"`
}

// createUser serves POST /api/v2/users.
//
// The connection decides which identifier is required and whether the request
// is valid at all, so it is resolved before anything else: Auth0 rejects a
// create against a federated connection, and an sms connection wants a phone
// number rather than an email.
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body createUserRequest
	dec := json.NewDecoder(r.Body)
	// Strict: a property this does not model would otherwise be accepted and
	// dropped, and the caller would read back a user missing what it sent.
	// Refusing names the gap instead of hiding it.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if body.Connection == "" {
		writeAuth0Error(w, http.StatusBadRequest, "connection is required")
		return
	}

	conn := s.connectionByName(body.Connection)
	if conn == nil {
		writeAuth0Error(w, http.StatusBadRequest, "the connection does not exist")
		return
	}
	if !createUserStrategies[conn.Strategy] {
		writeAuth0Error(w, http.StatusBadRequest,
			"users cannot be created in a "+conn.Strategy+" connection")
		return
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	phone := strings.TrimSpace(body.Phone)
	switch conn.Strategy {
	case "sms":
		if phone == "" {
			writeAuth0Error(w, http.StatusBadRequest, "phone_number is required for an sms connection")
			return
		}
		// Auth0 requires E.164 on the way in and refuses anything else rather
		// than normalizing it, so accepting "(214) 555-1234" here would pass
		// locally and 400 against a real tenant.
		if !e164Pattern.MatchString(phone) {
			writeAuth0Error(w, http.StatusBadRequest, "phone_number must be a valid E.164 number")
			return
		}
	default:
		if email == "" {
			writeAuth0Error(w, http.StatusBadRequest, "email is required for this connection")
			return
		}
		// Phone attributes belong to an SMS user. Storing them here would
		// return a mixed profile Auth0 refuses to create.
		if phone != "" || body.PhoneVerified != nil {
			writeAuth0Error(w, http.StatusBadRequest,
				"phone attributes are not supported on a "+conn.Strategy+" connection")
			return
		}
		// net/mail, not contact.IsEmail: that one decides email-versus-phone
		// and accepts any word, so "not-an-email" would pass. ParseAddress is
		// itself too permissive — it accepts mailbox syntax like
		// "Jane <jane@example.com>" — so the parse has to round-trip to the
		// address it was given.
		parsed, err := mail.ParseAddress(email)
		if err != nil || !strings.EqualFold(parsed.Address, email) {
			writeAuth0Error(w, http.StatusBadRequest, "email must be a valid address")
			return
		}
	}

	// Only a connection that requires a username accepts one, which neither
	// passwordless strategy does. Auth0 refuses the create rather than storing
	// a field it has no use for.
	if body.Username != "" {
		writeAuth0Error(w, http.StatusBadRequest,
			"username is not supported on a "+conn.Strategy+" connection")
		return
	}

	identifier := email
	if conn.Strategy == "sms" {
		identifier = phone
	}

	// One subject, used as the suffix of the root id and as the identity's own
	// user_id — the shape Auth0 returns, and what linking code addresses.
	subject := s.generateID()
	if body.ID != "" {
		// Auth0 takes this as the provider subject and returns a root id it
		// prefixes itself, so a caller supplying "abc" reads back
		// "email|abc" — not "abc" with an unrelated subject on the identity.
		subject = body.ID
	}
	userID := conn.Strategy + "|" + subject
	// Auth0 normalizes a profile name rather than storing an empty one, and the
	// login-created path already uses the identifier. Without this every token
	// for a pre-admitted member carries "name": "".
	name := body.Name
	if name == "" {
		name = identifier
	}

	now := time.Now().UTC().Format(time.RFC3339)
	user := &config.User{
		CreatedAt: now,
		UpdatedAt: now,
		// Prefixed with the provider, not the connection name: Auth0 returns
		// `email|...` even when the connection is called something else, and
		// the custom name lives on the identity instead.
		ID:            userID,
		Email:         email,
		Phone:         phone,
		Name:          name,
		GivenName:     body.GivenName,
		FamilyName:    body.FamilyName,
		Nickname:      body.Nickname,
		Username:      body.Username,
		Picture:       body.Picture,
		EmailVerified: body.EmailVerified,
		PhoneVerified: body.PhoneVerified != nil && *body.PhoneVerified,
		Blocked:       body.Blocked,
		AppMetadata:   body.AppMetadata,
		UserMetadata:  body.UserMetadata,
		Identities: []config.UserIdentity{{
			Connection: body.Connection,
			Provider:   conn.Strategy,
			UserID:     subject,
			IsSocial:   false,
		}},
	}

	s.mu.Lock()
	// Re-checked under the lock that inserts: the connection was read from a
	// clone, and a DELETE landing in between would finish its sweep of that
	// connection's users before this one is written, leaving a user pointing
	// at a connection that no longer exists.
	if !s.connectionExistsLocked(body.Connection) {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusBadRequest, "the connection does not exist")
		return
	}
	// A supplied id that already exists belongs to someone else: overwriting
	// it would hand the new profile that user's organization memberships,
	// which stay keyed to the id.
	if body.ID != "" {
		if _, taken := s.users[userID]; taken {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusConflict, "the user already exists")
			return
		}
	}
	// Auth0 refuses a second user for the same identifier in the same
	// connection. A consumer that loses this race re-reads and uses the
	// winner, so the status is what tells the two apart.
	for _, u := range s.matchUsersLocked(identifier) {
		for _, id := range u.Identities {
			if id.Connection == body.Connection {
				s.mu.Unlock()
				writeAuth0Error(w, http.StatusConflict, "the user already exists")
				return
			}
		}
	}
	s.users[user.ID] = user
	out := user.Clone()
	s.mu.Unlock()

	// Serialized outside the lock: holding the only write lock while a slow
	// reader drains the body stalls every stateful route.
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
}

// connectionByName resolves a connection by its name, the identifier the users
// endpoint takes.
func (s *Server) connectionByName(name string) *config.Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.connections {
		if c.Name == name {
			return c.Clone()
		}
	}
	return nil
}

// handleUsersByEmail serves GET /api/v2/users-by-email.
//
// Auth0 answers with a bare array here, not the paginated envelope the other
// list endpoints use, and the SDK decodes it as such.
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

	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		writeAuth0Error(w, http.StatusBadRequest, "email query parameter is required")
		return
	}

	s.mu.RLock()
	out := make([]config.User, 0, 1)
	for _, u := range s.users {
		// Exact, not case-insensitive. Auth0 lowercases the addresses it
		// stores itself but keeps a federated provider's capitalization, and
		// this endpoint matches what is stored — so a caller querying the wrong
		// case must miss here too, or it passes locally and returns nothing
		// against a real tenant.
		if strings.TrimSpace(u.Email) == email {
			out = append(out, *u.Clone())
		}
	}
	s.mu.RUnlock()

	// Map iteration order is random and a consumer picking the first match
	// would behave differently run to run.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	_ = json.NewEncoder(w).Encode(out)
}

// markIdentifierVerified records that a delivered one-time code proved control
// of the identifier, and returns the updated user.
func (s *Server) markIdentifierVerified(userID, identifier string) *config.User {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[userID]
	if !ok {
		return nil
	}
	if strings.Contains(identifier, "@") {
		u.EmailVerified = true
	} else {
		u.PhoneVerified = true
	}
	return u.Clone()
}

// isPasswordlessLogin reports whether this login completed a one-time code for
// the given user.
//
// The user matters because an omitted connection is the passwordless default
// yet can still resolve to a federated profile when that is all the address
// has. Verifying then would rewrite a flag the IdP owns.
func (s *Server) isPasswordlessLogin(connection string, user *config.User) bool {
	if user == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	if connection != "" {
		return s.isPasswordlessConnection(connection)
	}
	for _, id := range user.Identities {
		if s.isPasswordlessConnection(id.Connection) {
			return true
		}
	}
	// No identities at all is the mock's own auto-created shape, which is
	// passwordless by construction.
	return len(user.Identities) == 0
}

// connectionExistsLocked reports whether a connection with this name is still
// present. Requires the caller to hold the lock.
func (s *Server) connectionExistsLocked(name string) bool {
	for _, c := range s.connections {
		if c.Name == name {
			return true
		}
	}
	return false
}
