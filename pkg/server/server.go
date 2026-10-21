package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

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
	// Connection is the one signed in through.
	Connection string
	// Query is the /authorize request as sent, for Actions' event.request.query.
	Query string
	// SessionID names the login session this code belongs to: Actions see it
	// as event.session.id, the ID token carries it as sid, and every token
	// refreshed from this login keeps it.
	SessionID string
	// LoginLog is the sign-in record for this login, emitted once the
	// post-login Action has run: Auth0 logs a denied login as a failure. Nil
	// for codes minted without the login UI.
	LoginLog map[string]any
}

// refreshTokenState carries the bindings of the login that issued the token,
// so a refresh cannot re-scope it to another client or organization.
type refreshTokenState struct {
	UserID         string
	OrgID          string
	ClientID       string
	IncludeIDToken bool
	// SessionID is the login session the token was issued in.
	SessionID string
	// Connection is the one signed in through.
	Connection string
	// Scope is the scope granted at login; a refresh re-issues it, as
	// Auth0 does when the refresh request omits scope.
	Scope string
	// Family is shared by a refresh token and every token rotated from it.
	// Auth0 revokes the whole family when a retired token is used again.
	Family string
}

// retiredRefreshToken is a refresh token that a rotation replaced.
type retiredRefreshToken struct {
	State     *refreshTokenState
	RetiredAt time.Time
}

const (
	defaultDeviceCodeLifetime = 15 * time.Minute
	devicePollInterval        = 5 * time.Second

	deviceTransactionPending  = "pending"
	deviceTransactionApproved = "approved"
	deviceTransactionDenied   = "denied"
	deviceTransactionExpired  = "expired"
	deviceTransactionConsumed = "consumed"
)

// deviceTransaction carries one RFC 8628 authorization request from issuance
// through browser approval and its one-time token exchange.
type deviceTransaction struct {
	DeviceCode     string
	UserCode       string
	ClientID       string
	Audience       string
	Scope          string
	OrgID          string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	Interval       time.Duration
	NextPollAt     time.Time
	Status         string
	ApprovedBy     string
	FailedAttempts int
	BlockedUntil   time.Time
}

type Server struct {
	cfg        *config.Config
	privateKey *rsa.PrivateKey
	templates  *templates.Loader

	pending       map[string]string
	authCodes     map[string]*authCode
	refreshTokens map[string]*refreshTokenState
	// retiredRefreshTokens are the tokens rotations replaced, for reuse detection.
	retiredRefreshTokens map[string]*retiredRefreshToken
	deviceCodes          map[string]*deviceTransaction

	actions *actionStore
	teps    *tokenExchangeProfiles

	users         map[string]*config.User
	organizations map[string]*config.Organization
	connections   map[string]*config.Connection
	members       map[string][]config.OrganizationMember
	clients       map[string]*config.Client
	clientGrants  map[string]*clientGrant
	roles         map[string]*config.Role

	orgConnections map[string][]config.OrganizationConnection
	// keyed by org id, in creation order
	invitations map[string][]config.OrganizationInvitation

	selfServiceProfiles map[string]*selfServiceProfile
	// keyed by ticket id
	ssoTickets map[string]*ssoTicket

	logStreams        map[string]*logStream
	logDeliveryClient *http.Client
	logRetryBackoff   time.Duration
	// logDeliveries tracks in-flight deliveries, so tests wait on them
	// instead of sleeping.
	logDeliveries sync.WaitGroup

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
		cfg:                  cfg,
		privateKey:           key,
		templates:            tmpl,
		pending:              make(map[string]string),
		authCodes:            make(map[string]*authCode),
		actions:              newActionStore(),
		teps:                 &tokenExchangeProfiles{profiles: map[string]*tokenExchangeProfile{}},
		refreshTokens:        make(map[string]*refreshTokenState),
		retiredRefreshTokens: make(map[string]*retiredRefreshToken),
		deviceCodes:          make(map[string]*deviceTransaction),
		users:                users,
		organizations:        organizations,
		connections:          connections,
		members:              members,
		clients:              clients,
		clientGrants:         map[string]*clientGrant{},
		roles:                roles,
		orgConnections:       orgConnections,
		invitations:          make(map[string][]config.OrganizationInvitation),

		selfServiceProfiles: make(map[string]*selfServiceProfile),
		ssoTickets:          make(map[string]*ssoTicket),

		logStreams:        make(map[string]*logStream),
		logDeliveryClient: logDeliveryClient(),
		logRetryBackoff:   defaultLogStreamBackoff,
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
	mux.HandleFunc("/oauth/device/code", s.handleDeviceAuthorization)
	mux.HandleFunc("/oauth/token", s.handleToken)
	mux.HandleFunc("/device", s.handleDeviceVerification)
	mux.HandleFunc("/userinfo", s.handleUserInfo)
	mux.HandleFunc("/v2/logout", s.handleLogout)

	mux.HandleFunc("/api/v2/organizations", s.handleOrganizations)
	mux.HandleFunc("/api/v2/organizations/", s.routeOrganizationPath)
	mux.HandleFunc("/api/v2/connections", s.handleConnections)
	mux.HandleFunc("/api/v2/connections/", s.handleConnection)
	mux.HandleFunc("/api/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/organizations") {
			s.handleUserOrganizations(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/identities") {
			s.handleUserIdentities(w, r)
			return
		}
		s.handleUser(w, r)
	})
	mux.HandleFunc("/api/v2/users", s.handleUsers)
	mux.HandleFunc("/api/v2/users-by-email", s.handleUsersByEmail)
	mux.HandleFunc("/api/v2/clients", s.handleClients)
	mux.HandleFunc("/api/v2/client-grants", s.handleClientGrants)
	mux.HandleFunc("/api/v2/clients/", s.handleClient)
	mux.HandleFunc("/api/v2/roles", s.handleRoles)
	mux.HandleFunc("/api/v2/roles/", s.handleRole)
	mux.HandleFunc("/api/v2/log-streams", s.handleLogStreams)
	mux.HandleFunc("/api/v2/log-streams/", s.handleLogStream)
	mux.HandleFunc("/api/v2/self-service-profiles", s.handleSelfServiceProfiles)
	mux.HandleFunc("/api/v2/self-service-profiles/", s.handleSelfServiceProfile)
	mux.HandleFunc("/self-service/connections-flow", s.handleConnectionsFlow)
	s.registerActionsAPI(mux)
	s.registerTokenExchangeProfiles(mux)

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

// findUserLocked requires the caller to hold the lock.
func (s *Server) findUserLocked(identifier string) *config.User {
	// Determine if email or phone
	if contact.IsEmail(identifier) {
		// Case-insensitive, as Auth0 treats email identifiers; an exact
		// compare would miss an account whose stored casing differs.
		for _, u := range s.users {
			if strings.EqualFold(u.Email, identifier) {
				return u.Clone()
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
						return u.Clone()
					}
				}
			}
		}
	}
	return nil
}

// passwordlessConnectionNameLocked names the tenant's connection for the
// strategy, preferring one named after it. Caller holds the lock.
func (s *Server) passwordlessConnectionNameLocked(strategy string) string {
	name := ""
	for _, c := range s.connections {
		if c.Strategy != strategy {
			continue
		}
		if c.Name == strategy {
			return c.Name
		}
		if name == "" || c.Name < name {
			name = c.Name
		}
	}
	if name == "" {
		return strategy
	}
	return name
}

// autoCreateUserLocked provisions a passwordless user on connName, or the
// strategy's connection when empty. Caller holds the write lock.
func (s *Server) autoCreateUserLocked(identifier, connName string) *config.User {
	isEmail := contact.IsEmail(identifier)
	strategy := config.StrategySMS
	if isEmail {
		strategy = config.StrategyEmail
	}
	if connName == "" {
		connName = s.passwordlessConnectionNameLocked(strategy)
	}
	userIDPart := s.generateID()
	now := auth0Timestamp(time.Now())
	user := &config.User{
		ID:           strategy + "|" + userIDPart,
		Name:         identifier,
		AppMetadata:  config.AppMetadata{},
		UserMetadata: make(map[string]interface{}),
		CreatedAt:    now,
		UpdatedAt:    now,
		Identities:   []config.UserIdentity{{Connection: connName, Provider: strategy, UserID: userIDPart}},
	}
	if isEmail {
		// Auth0 stores the addresses it manages in lower case.
		user.Email = strings.ToLower(identifier)
		user.EmailVerified = true
	} else {
		normalizedPhone, err := contact.NormalizePhoneToE164(identifier)
		if err != nil {
			log.Printf("Failed to normalize phone %s: %v", identifier, err)
			normalizedPhone = identifier
		}
		user.Phone = normalizedPhone
		verified := true
		user.PhoneVerified = &verified
	}

	s.users[user.ID] = user.Clone()
	log.Printf("Auto-created user: %s (%s)", user.ID, identifier)
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
	s.authCodes[code] = &authCode{User: *user, Scope: scope, OrgID: orgID, ClientID: clientID, SessionID: "sess_" + s.generateID()}
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
	if user.CreatedAt != "" {
		user.UpdatedAt = auth0Timestamp(time.Now())
	}

	return nil
}

func (s *Server) SignToken(claims map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "key-1"
	return token.SignedString(s.privateKey)
}
