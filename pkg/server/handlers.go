package server

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Issuer + "authorize",
		"token_endpoint":                        s.cfg.Issuer + "oauth/token",
		"userinfo_endpoint":                     s.cfg.Issuer + "userinfo",
		"jwks_uri":                              s.cfg.Issuer + ".well-known/jwks.json",
		"end_session_endpoint":                  s.cfg.Issuer + "v2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
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

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sessionID := s.generateID()
		s.pending[sessionID] = r.URL.RawQuery

		data := map[string]interface{}{
			"SessionID": sessionID,
			"Branding":  s.cfg.Branding,
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

		originalQuery, exists := s.pending[sessionID]
		if !exists {
			http.Error(w, "Invalid session", 400)
			return
		}

		if code != "" {
			if code == "123456" {
				user := s.findUser(identifier)
				if user != nil {
					params, _ := url.ParseQuery(originalQuery)
					authCode := s.generateID()
					s.verified[authCode] = *user

					if codeChallenge := params.Get("code_challenge"); codeChallenge != "" {
						s.verifiers[authCode] = codeChallenge
					}
					if nonce := params.Get("nonce"); nonce != "" {
						s.nonces[authCode] = nonce
					}

					redirectURI := params.Get("redirect_uri")
					redirectURL, _ := url.Parse(redirectURI)
					query := redirectURL.Query()
					query.Set("code", authCode)
					if state := params.Get("state"); state != "" {
						query.Set("state", state)
					}
					redirectURL.RawQuery = query.Encode()

					delete(s.pending, sessionID)
					http.Redirect(w, r, redirectURL.String(), http.StatusFound)
					return
				}
			}
			http.Error(w, "Invalid code", 400)
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

	_ = r.ParseForm()
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")

	user, exists := s.verified[code]
	if !exists {
		http.Error(w, "Invalid code", 400)
		return
	}

	now := time.Now()
	ns := strings.TrimSuffix(s.cfg.Issuer, "/") + "/"

	idClaims := jwt.MapClaims{
		"sub":            user.ID,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"name":           user.Name,
		"iss":            s.cfg.Issuer,
		"aud":            clientID,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"auth_time":      now.Unix(),
	}

	if user.Phone != "" {
		idClaims["phone_number"] = user.Phone
		idClaims["phone_number_verified"] = true
	}

	if user.Picture != "" {
		idClaims["picture"] = user.Picture
	}

	if nonce, ok := s.nonces[code]; ok {
		idClaims["nonce"] = nonce
	}

	nameParts := strings.Split(user.Name, " ")
	if len(nameParts) > 0 {
		idClaims["given_name"] = nameParts[0]
	}
	if len(nameParts) > 1 {
		idClaims["family_name"] = nameParts[1]
	}

	if user.AppMetadata.TenantID != "" {
		idClaims[ns+"tenant_id"] = user.AppMetadata.TenantID
	}
	if user.AppMetadata.Role != "" {
		idClaims[ns+"role"] = user.AppMetadata.Role
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	idToken.Header["kid"] = "key-1"

	accessClaims := jwt.MapClaims{
		"sub":   user.ID,
		"iss":   s.cfg.Issuer,
		"aud":   s.cfg.Audience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "openid profile email",
	}

	if user.AppMetadata.TenantID != "" {
		accessClaims[ns+"tenant_id"] = user.AppMetadata.TenantID
	}
	if user.AppMetadata.Role != "" {
		accessClaims[ns+"role"] = user.AppMetadata.Role
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = "key-1"

	idTokenString, err := idToken.SignedString(s.privateKey)
	if err != nil {
		http.Error(w, "Token generation failed", 500)
		return
	}

	accessTokenString, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		http.Error(w, "Token generation failed", 500)
		return
	}

	delete(s.verified, code)
	delete(s.verifiers, code)
	delete(s.nonces, code)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": accessTokenString,
		"id_token":     idTokenString,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || auth[:7] != "Bearer " {
		http.Error(w, "Invalid authorization", http.StatusUnauthorized)
		return
	}

	tokenString := auth[7:]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &s.privateKey.PublicKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":          claims["sub"],
		"email":        claims["email"],
		"name":         claims["name"],
		"phone_number": claims["phone_number"],
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("returnTo")
	if returnTo == "" {
		returnTo = strings.TrimSuffix(s.cfg.Issuer, "/")
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}
