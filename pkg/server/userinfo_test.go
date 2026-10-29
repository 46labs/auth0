package server

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// audiences is a token's aud claim as a list, whichever form it was sent in.
func audiences(t *testing.T, c jwt.MapClaims) []string {
	t.Helper()
	aud, err := c.GetAudience()
	if err != nil || len(aud) == 0 {
		t.Fatalf("aud = %v (%v)", c["aud"], err)
	}
	return aud
}

// userInfo calls /userinfo with token over method (OIDC endpoints are raw
// HTTP; the SDK does not cover them).
func userInfo(t *testing.T, base, method, token string) (int, http.Header, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, resp.Header, body
}

// TestUserInfo_ClaimsFollowScope: Auth0 reads the profile from the user store
// and releases each standard claim only under its scope. test_user_1 signs in
// by phone and also holds an email.
func TestUserInfo_ClaimsFollowScope(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	tests := []struct {
		scope string
		want  map[string]any
	}{
		{"openid", map[string]any{"sub": "test_user_1"}},
		{"openid profile", map[string]any{"sub": "test_user_1", "name": "Test User", "nickname": "test"}},
		{"openid email", map[string]any{"sub": "test_user_1", "email": "test@example.test", "email_verified": true}},
		{"openid phone", map[string]any{"sub": "test_user_1", "phone_number": "+14155551234", "phone_number_verified": true}},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			st, tok := loginWithScope(t, ts, tt.scope, "")
			if st != 200 {
				t.Fatalf("token: %d %v", st, tok)
			}
			if aud := audiences(t, claims(t, tok["access_token"])); !slices.Contains(aud, ts.URL+"/userinfo") {
				t.Fatalf("openid access token aud %v lacks /userinfo", aud)
			}
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				st, _, body := userInfo(t, ts.URL, method, tok["access_token"].(string))
				delete(body, "updated_at")
				if st != 200 || !maps.Equal(body, tt.want) {
					t.Fatalf("%s userinfo = %d %v, want %v", method, st, body, tt.want)
				}
			}
		})
	}
}

// TestUserInfo_Rejects: Auth0 answers 401 with a Bearer challenge for a
// token it would not have issued for /userinfo.
func TestUserInfo_Rejects(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	sign := func(sub string, aud any) string {
		tok, err := srv.SignToken(map[string]any{
			"sub": sub, "iss": srv.cfg.Issuer, "aud": aud, "scope": "openid email",
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	_, noOpenID := loginWithScope(t, ts, "profile email", "")

	tests := []struct {
		name  string
		token string
	}{
		{"API audience only", sign("test_user_1", srv.cfg.Audience)},
		{"login without openid", noOpenID["access_token"].(string)},
		{"unknown user", sign("email|gone", []string{srv.cfg.Audience, ts.URL + "/userinfo"})},
		{"not a JWT", "invalid_token_xyz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, h, _ := userInfo(t, ts.URL, http.MethodGet, tt.token)
			if st != 401 || !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
				t.Fatalf("userinfo = %d %q, want 401 with a Bearer challenge", st, h.Get("WWW-Authenticate"))
			}
		})
	}
}

// TestUserInfo_SignedUpByEmail: an address the tenant has not seen becomes an
// email| user, and its access token reads that address back from /userinfo.
func TestUserInfo_SignedUpByEmail(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	srv.mu.Lock()
	user := srv.autoCreateUserLocked("New.Person@Example.test", "")
	srv.mu.Unlock()
	if !strings.HasPrefix(user.ID, "email|") {
		t.Fatalf("new email user id %q, want email|", user.ID)
	}
	tok, err := srv.SignToken(srv.accessTokenClaims(user, srv.cfg.Audience, "openid email", "", time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	st, _, body := userInfo(t, ts.URL, http.MethodGet, tok)
	if st != 200 || body["email"] != "new.person@example.test" || body["email_verified"] != true {
		t.Fatalf("userinfo = %d %v", st, body)
	}
}

// TestUserInfo_CORS: a browser app may read /userinfo, so its preflight is
// answered and the response names the allowed origin.
func TestUserInfo_CORS(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/userinfo", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "authorization")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "http://localhost:3000" ||
		!strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight = %d %v", resp.StatusCode, resp.Header)
	}
}
