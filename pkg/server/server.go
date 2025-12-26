package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/templates"
	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	cfg        *config.Config
	privateKey *rsa.PrivateKey
	templates  *templates.Loader
	pending    map[string]string
	verified   map[string]config.User
	verifiers  map[string]string
	nonces     map[string]string
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

	return &Server{
		cfg:        cfg,
		privateKey: key,
		templates:  tmpl,
		pending:    make(map[string]string),
		verified:   make(map[string]config.User),
		verifiers:  make(map[string]string),
		nonces:     make(map[string]string),
	}, nil
}

func (s *Server) Start() error {
	http.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	http.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	http.HandleFunc("/authorize", s.handleAuthorize)
	http.HandleFunc("/oauth/token", s.handleToken)
	http.HandleFunc("/userinfo", s.handleUserInfo)
	http.HandleFunc("/v2/logout", s.handleLogout)

	addr := fmt.Sprintf(":%d", s.cfg.Port)
	log.Printf("Starting server on %s (issuer: %s)", addr, s.cfg.Issuer)
	return http.ListenAndServe(addr, nil)
}

func (s *Server) generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *Server) findUser(phone string) *config.User {
	for _, u := range s.cfg.Users {
		if u.Phone == phone {
			return &u
		}
	}
	return nil
}

func (s *Server) SignToken(claims map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "key-1"
	return token.SignedString(s.privateKey)
}
