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

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/templates"
	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	cfg        *config.Config
	privateKey *rsa.PrivateKey
	templates  *templates.Loader

	pending   map[string]string
	verified  map[string]config.User
	verifiers map[string]string
	nonces    map[string]string

	users         map[string]*config.User
	organizations map[string]*config.Organization
	connections   map[string]*config.Connection
	members       map[string][]config.OrganizationMember

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

	return &Server{
		cfg:           cfg,
		privateKey:    key,
		templates:     tmpl,
		pending:       make(map[string]string),
		verified:      make(map[string]config.User),
		verifiers:     make(map[string]string),
		nonces:        make(map[string]string),
		users:         users,
		organizations: organizations,
		connections:   connections,
		members:       members,
	}, nil
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
	mux.HandleFunc("/api/v2/organizations/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/members/") && strings.Contains(r.URL.Path, "/roles") {
			s.handleOrganizationMemberRoles(w, r)
		} else if strings.Contains(r.URL.Path, "/members") {
			s.handleOrganizationMembers(w, r)
		} else {
			s.handleOrganization(w, r)
		}
	})
	mux.HandleFunc("/api/v2/connections", s.handleConnections)
	mux.HandleFunc("/api/v2/users/", s.handleUser)

	return mux
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	log.Printf("Starting server on %s (issuer: %s)", addr, s.cfg.Issuer)
	log.Printf("Management API available at /api/v2/*")
	return http.ListenAndServe(addr, s.Handler())
}

func (s *Server) generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *Server) findUser(identifier string) *config.User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.users {
		if u.Phone == identifier || u.Email == identifier {
			return u
		}
	}
	return nil
}

func (s *Server) autoCreateUser(identifier string) *config.User {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	if strings.HasPrefix(identifier, "+") {
		user.Phone = identifier
		user.Identities = []config.UserIdentity{
			{
				Connection: "sms",
				Provider:   "sms",
				UserID:     userIDPart,
				IsSocial:   false,
			},
		}
	} else if strings.Contains(identifier, "@") {
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
		// Default to email
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
	}

	s.users[userID] = user
	log.Printf("Auto-created user: %s (%s)", userID, identifier)
	return user
}

func (s *Server) getUserByID(userID string) *config.User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if user, ok := s.users[userID]; ok {
		return user
	}
	return nil
}

// SetUser adds or updates a user in the mock server (for testing)
func (s *Server) SetUser(userID string, user *config.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[userID] = user
}

// GetOrgMembers returns the members of an organization (for testing)
func (s *Server) GetOrgMembers(orgID string) []config.OrganizationMember {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if members, ok := s.members[orgID]; ok {
		return members
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
