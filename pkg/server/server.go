package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/contact"
	"github.com/46labs/auth0/pkg/templates"
	"github.com/golang-jwt/jwt/v5"
)

// authCode is the state a pending authorization code carries from the
// /authorize redirect to its single exchange at /oauth/token. The client,
// organization and connection are the ones the login was authorized for; the
// exchange and the refresh path must not be able to substitute others.
type authCode struct {
	User          config.User
	CodeChallenge string
	Nonce         string
	Scope         string
	ClientID      string
	OrgID         string
	ConnectionID  string
}

// refreshTokenState carries the bindings of the login that issued the token,
// so a refresh cannot re-scope it to another client or organization.
type refreshTokenState struct {
	UserID   string
	OrgID    string
	ClientID string
}

type Server struct {
	cfg        *config.Config
	privateKey *rsa.PrivateKey
	templates  *templates.Loader

	pending       map[string]string
	authCodes     map[string]*authCode
	refreshTokens map[string]*refreshTokenState

	users map[string]*config.User
	// Actions state. Held as decoded JSON because the mock never executes the
	// source; it only has to round-trip what a reconciler wrote.
	actions               map[string]map[string]any
	actionBindings        map[string][]map[string]any
	tokenExchangeProfiles map[string]map[string]any
	organizations         map[string]*config.Organization
	connections           map[string]*config.Connection
	members               map[string][]config.OrganizationMember
	clients               map[string]*config.Client
	clientGrants          map[string]*clientGrant
	roles                 map[string]*config.Role

	orgConnections map[string][]config.OrganizationConnection
	// keyed by org id, in creation order
	invitations map[string][]config.OrganizationInvitation

	mu sync.RWMutex
}

func New(cfg *config.Config) (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	tmpl, err := templates.New(cfg)
	if err != nil {
		return nil, err
	}

	users := make(map[string]*config.User)
	for i := range cfg.Users {
		users[cfg.Users[i].ID] = &cfg.Users[i]
	}

	organizations := make(map[string]*config.Organization)
	for i := range cfg.Organizations {
		organizations[cfg.Organizations[i].ID] = &cfg.Organizations[i]
	}

	connections := make(map[string]*config.Connection)
	for i := range cfg.Connections {
		connections[cfg.Connections[i].ID] = &cfg.Connections[i]
	}

	members := make(map[string][]config.OrganizationMember)
	for _, member := range cfg.Members {
		members[member.OrgID] = append(members[member.OrgID], member)
	}

	clients := make(map[string]*config.Client)
	for i := range cfg.Clients {
		clients[cfg.Clients[i].ClientID] = &cfg.Clients[i]
	}

	roles := make(map[string]*config.Role)
	for i := range cfg.Roles {
		roles[cfg.Roles[i].ID] = &cfg.Roles[i]
	}

	orgConnections := buildOrgConnections(cfg)

	return &Server{
		cfg:            cfg,
		privateKey:     key,
		templates:      tmpl,
		pending:        make(map[string]string),
		authCodes:      make(map[string]*authCode),
		refreshTokens:  make(map[string]*refreshTokenState),
		users:          users,
		organizations:  organizations,
		connections:    connections,
		members:        members,
		clients:        clients,
		clientGrants:   map[string]*clientGrant{},
		roles:          roles,
		orgConnections: orgConnections,
		invitations:    make(map[string][]config.OrganizationInvitation),

		actions:               map[string]map[string]any{},
		actionBindings:        map[string][]map[string]any{},
		tokenExchangeProfiles: map[string]map[string]any{},
	}, nil
}

// buildOrgConnections seeds the enabled_connections pairings from each
// connection's Organizations list. An explicit OrganizationConnections entry
// wins over a derived pairing for the same pair.
func buildOrgConnections(cfg *config.Config) map[string][]config.OrganizationConnection {
	out := make(map[string][]config.OrganizationConnection)

	enabled := func(orgID, connID string) bool {
		for _, oc := range out[orgID] {
			if oc.ConnectionID == connID {
				return true
			}
		}
		return false
	}

	for _, declared := range cfg.OrganizationConnections {
		if declared.OrgID == "" || declared.ConnectionID == "" ||
			enabled(declared.OrgID, declared.ConnectionID) {
			continue
		}
		oc := declared.Resolve()
		out[oc.OrgID] = append(out[oc.OrgID], oc)
	}

	for _, conn := range cfg.Connections {
		for _, orgID := range conn.Organizations {
			if enabled(orgID, conn.ID) {
				continue
			}
			out[orgID] = append(out[orgID], config.OrganizationConnection{
				OrgID:        orgID,
				ConnectionID: conn.ID,
				ShowAsButton: true,
			})
		}
	}

	return out
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/token", s.handleToken)
	mux.HandleFunc("/userinfo", s.handleUserInfo)
	mux.HandleFunc("/v2/logout", s.handleLogout)

	mux.HandleFunc("/api/v2/organizations", s.handleOrganizations)
	mux.HandleFunc("/api/v2/organizations/", s.routeOrganizationPath)
	mux.HandleFunc("/api/v2/connections", s.handleConnections)
	mux.HandleFunc("/api/v2/connections/", s.handleConnection)
	mux.HandleFunc("/api/v2/actions/", s.routeActionsPath)
	mux.HandleFunc("/api/v2/token-exchange-profiles", s.handleTokenExchangeProfiles)
	mux.HandleFunc("/api/v2/users", s.handleUsersCollection)
	mux.HandleFunc("/api/v2/users-by-email", s.handleUsersByEmail)
	mux.HandleFunc("/api/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/organizations") {
			s.handleUserOrganizations(w, r)
			return
		}
		s.handleUser(w, r)
	})
	mux.HandleFunc("/api/v2/clients", s.handleClients)
	mux.HandleFunc("/api/v2/client-grants", s.handleClientGrants)
	mux.HandleFunc("/api/v2/clients/", s.handleClient)
	mux.HandleFunc("/api/v2/roles", s.handleRoles)
	mux.HandleFunc("/api/v2/roles/", s.handleRole)

	return mux
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	log.Printf("Starting server on %s (issuer: %s)", addr, s.cfg.Issuer)
	log.Printf("Management API available at /api/v2/*")
	return http.ListenAndServe(addr, s.Handler())
}

// generateID mints an opaque identifier. Unpadded: real Auth0 ids carry no
// "==" tail, and these land in URL paths and query strings.
func (s *Server) generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) findUser(identifier string) *config.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findUserLocked(identifier)
}

// findUserForConnection resolves the identifier to the identity held in the
// named connection.
//
// One address can exist in several connections — an enterprise identity and a
// passwordless one, say — and they are different users to Auth0. Matching on
// the identifier alone picks whichever the map yields first, so a passwordless
// login could be issued a token for the SSO user. An empty connection keeps the
// old behaviour for callers that have none.
func (s *Server) findUserForConnection(identifier, connection string) *config.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findUserForConnectionLocked(identifier, connection)
}

// findUserStrictlyForConnectionLocked resolves only an identity that actually
// names the connection, or one with no recorded provenance.
//
// Used where picking the wrong subject grants something: an invitation carries
// a role and an organization membership, so falling back to another
// connection's user would hand both to someone the invitation was not for. The
// login path keeps the looser rule, because refusing there only breaks sign-in
// for fixtures that predate identities.
func (s *Server) findUserStrictlyForConnectionLocked(identifier, connection string) *config.User {
	matches := s.matchUsersLocked(identifier)
	for _, u := range matches {
		for _, id := range u.Identities {
			if id.Connection == connection {
				return u.Clone()
			}
		}
	}
	for _, u := range matches {
		if len(u.Identities) == 0 {
			return u.Clone()
		}
	}
	return nil
}

// findUserForConnectionLocked requires the caller to hold the lock.
func (s *Server) findUserForConnectionLocked(identifier, connection string) *config.User {

	matches := s.matchUsersLocked(identifier)
	if len(matches) == 0 {
		return nil
	}

	if connection == "" {
		// The normal passwordless flow omits the parameter, so "no connection"
		// still means an email or SMS login. Preferring that identity keeps an
		// enterprise subject that happens to sort first from being issued the
		// token — and then marked verified by a code it never received.
		for _, u := range matches {
			for _, id := range u.Identities {
				if s.isPasswordlessConnection(id.Connection) {
					return u.Clone()
				}
			}
		}
		return matches[0].Clone()
	}

	// An identity naming this connection is the answer outright.
	for _, u := range matches {
		for _, id := range u.Identities {
			if id.Connection == connection {
				return u.Clone()
			}
		}
	}

	// Absent provenance is not a mismatch. The documented YAML user shape omits
	// identities entirely, so a configured user says nothing about which
	// connection it belongs to and cannot be refused on that basis — refusing
	// would create a duplicate that lacks the original's org membership.
	for _, u := range matches {
		if len(u.Identities) == 0 {
			return u.Clone()
		}
	}

	// Everything that matches names some other connection, so who decides
	// identity settles it.
	//
	// A passwordless connection is decided here: the mock can create the
	// identity itself, so returning another connection's user would mint a
	// token for the wrong subject when it should have created a new one.
	//
	// A federated connection is decided by the IdP, which the local identity
	// list cannot refute, so fall back rather than refuse a login that works.
	if s.isPasswordlessConnection(connection) {
		return nil
	}
	return matches[0].Clone()
}

// isPasswordlessConnection reports whether this connection is one the mock can
// create an identity in. Requires no lock of its own; callers hold it.
func (s *Server) isPasswordlessConnection(name string) bool {
	switch s.connectionStrategyLocked(name) {
	case "email", "sms":
		return true
	}
	// Unknown to the mock, so nothing here can be creating it.
	return false
}

// findUserLocked requires the caller to hold the lock.
func (s *Server) findUserLocked(identifier string) *config.User {
	matches := s.matchUsersLocked(identifier)
	if len(matches) == 0 {
		return nil
	}
	return matches[0].Clone()
}

// matchUsersLocked returns every user holding this identifier, ordered by id.
//
// Ordered because map iteration is random and several users can share one
// address across connections; an unordered answer makes the caller that takes
// the first match behave differently run to run. Requires the lock.
func (s *Server) matchUsersLocked(identifier string) []*config.User {
	var out []*config.User

	// Determine if email or phone
	if contact.IsEmail(identifier) {
		// Case-insensitive, as Auth0 treats email identifiers; an exact
		// compare would miss an account whose stored casing differs.
		for _, u := range s.users {
			if strings.EqualFold(u.Email, identifier) {
				out = append(out, u)
			}
		}
	} else {
		// Phone - normalize and compare
		normalizedIdentifier, err := contact.NormalizePhoneToE164(identifier)
		if err == nil {
			for _, u := range s.users {
				if u.Phone != "" {
					normalizedPhone, err := contact.NormalizePhoneToE164(u.Phone)
					if err == nil && normalizedPhone == normalizedIdentifier {
						out = append(out, u)
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// autoCreateUserForConnection records the connection the login actually used.
//
// The identity must name it, or a connection called anything but "email" or
// "sms" never matches on the next login: the lookup misses, this creates
// another subject, and the user's id changes every time they sign in.
func (s *Server) autoCreateUserForConnection(identifier, connection string) *config.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.autoCreateUserForConnectionLocked(identifier, connection)
}

// autoCreateUserForConnectionLocked requires the caller to hold the write lock.
func (s *Server) autoCreateUserForConnectionLocked(identifier, connection string) *config.User {
	// Another writer — a Management API create, say — can insert this identity
	// between the caller's lookup and this call, and a second one would be a
	// duplicate the caller never asked for.
	if existing := s.findUserForConnectionLocked(identifier, connection); existing != nil {
		return existing
	}

	// An identifier that contradicts the connection cannot be created: forcing
	// the name onto an inferred provider yields an impossible identity, such as
	// connection=email with provider=sms, that no Auth0 tenant would return.
	if connection != "" {
		isEmail := strings.Contains(identifier, "@")
		switch s.connectionStrategyLocked(connection) {
		case "email":
			if !isEmail {
				return nil
			}
		case "sms":
			if isEmail {
				return nil
			}
		}
	}

	user := s.autoCreateUserLocked(identifier)
	if user == nil || connection == "" {
		return user
	}
	stored, ok := s.users[user.ID]
	if !ok {
		return user
	}

	// autoCreateUserLocked infers a passwordless shape from the identifier
	// alone. Renaming only the identity's connection would leave a federated
	// user carrying an email/sms provider and an address this never verified —
	// a profile no tenant would return.
	strategy := s.connectionStrategyLocked(connection)
	federated := strategy != "" && strategy != "email" && strategy != "sms"
	for i := range stored.Identities {
		stored.Identities[i].Connection = connection
		if strategy != "" {
			stored.Identities[i].Provider = strategy
		}
	}
	if federated {
		// The IdP owns this, and nothing here checked it.
		stored.EmailVerified = false
	}
	return stored.Clone()
}

// connectionStrategyLocked returns a connection's strategy, or "" when the mock
// does not know it. Requires the lock.
func (s *Server) connectionStrategyLocked(name string) string {
	for _, c := range s.connections {
		if c.Name == name {
			return c.Strategy
		}
	}
	return ""
}

// autoCreateUserLocked requires the caller to hold the write lock.
func (s *Server) autoCreateUserLocked(identifier string) *config.User {
	userID := "auth0|" + s.generateID()
	userIDPart := userID[6:] // Extract part after "auth0|"

	user := &config.User{
		ID:            userID,
		Name:          identifier,
		EmailVerified: false,
		AppMetadata:   config.AppMetadata{},
		UserMetadata:  make(map[string]interface{}),
	}

	// Determine if email or phone based on format
	if contact.IsEmail(identifier) {
		user.Email = identifier
		user.EmailVerified = true
		user.Identities = []config.UserIdentity{
			{
				Connection: "email",
				Provider:   "email",
				UserID:     userIDPart,
				IsSocial:   false,
			},
		}
	} else {
		// Phone number - normalize before storing
		normalizedPhone, err := contact.NormalizePhoneToE164(identifier)
		if err != nil {
			log.Printf("Failed to normalize phone %s: %v", identifier, err)
			normalizedPhone = identifier // Store as-is if normalization fails
		}
		user.Phone = normalizedPhone
		user.Identities = []config.UserIdentity{
			{
				Connection: "sms",
				Provider:   "sms",
				UserID:     userIDPart,
				IsSocial:   false,
			},
		}
	}

	s.users[userID] = user.Clone()
	log.Printf("Auto-created user: %s (%s)", userID, identifier)
	return user
}

// getUserByID returns a copy of the stored user, or nil when unknown. The copy
// lets callers read it after the lock is released without racing a PATCH.
func (s *Server) getUserByID(userID string) *config.User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if user, ok := s.users[userID]; ok {
		return user.Clone()
	}
	return nil
}

// IssueAuthCode mints an authorization code without driving the login UI, so
// tests can exercise the token endpoint directly. An empty clientID leaves the
// code unbound.
func (s *Server) IssueAuthCode(userID, scope, orgID, clientID string) string {
	user := s.getUserByID(userID)
	if user == nil {
		return ""
	}

	code := s.generateID()
	s.mu.Lock()
	s.authCodes[code] = &authCode{User: *user, Scope: scope, OrgID: orgID, ClientID: clientID}
	s.mu.Unlock()
	return code
}

// SetOrgConnectionForTest enables a connection on an organization (for tests).
func (s *Server) SetOrgConnectionForTest(oc config.OrganizationConnection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgConnections[oc.OrgID] = append(s.orgConnections[oc.OrgID], oc)
}

// SetUser adds or updates a user in the mock server (for testing)
func (s *Server) SetUser(userID string, user *config.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[userID] = user
}

// GetOrgMembers returns a copy of an organization's members (for testing).
func (s *Server) GetOrgMembers(orgID string) []config.OrganizationMember {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if members, ok := s.members[orgID]; ok {
		out := make([]config.OrganizationMember, len(members))
		copy(out, members)
		return out
	}
	return []config.OrganizationMember{}
}

func (s *Server) updateUserMetadata(userID string, appMetadata *config.AppMetadata, userMetadata map[string]interface{}, blocked *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}

	if appMetadata != nil {
		user.AppMetadata = *appMetadata
	}

	if userMetadata != nil {
		if user.UserMetadata == nil {
			user.UserMetadata = make(map[string]interface{})
		}
		for k, v := range userMetadata {
			user.UserMetadata[k] = v
		}
	}

	if blocked != nil {
		user.Blocked = blocked
	}

	return nil
}

func (s *Server) SignToken(claims map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "key-1"
	return token.SignedString(s.privateKey)
}
