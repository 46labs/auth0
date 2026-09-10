package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

const exNS = "https://auth.example.test/"
const exSubjectType = "urn:pee:token-type:platform-admin"

func exchangeServer(t *testing.T, ex *config.TokenExchangeAction) *Server {
	t.Helper()
	if ex != nil && ex.SubjectTokenType == "" {
		ex.SubjectTokenType = exSubjectType
	}
	cfg := &config.Config{
		Issuer:   "https://auth.example.test/",
		Audience: "https://api.example.test",
		Organizations: []config.Organization{
			{ID: "org_1", Name: "org-one"},
			{ID: "org_2", Name: "org-two"},
		},
		Clients: []config.Client{{ClientID: "spa_app"}},
		Actions: config.Actions{TokenExchange: ex},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func (s *Server) signSubject(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["iss"] = s.cfg.Issuer
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["iat"] = time.Now().Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "key-1"
	str, err := tok.SignedString(s.privateKey)
	if err != nil {
		t.Fatalf("sign subject: %v", err)
	}
	return str
}

func doExchange(t *testing.T, srv *Server, subjectToken, org string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", tokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", exSubjectType)
	form.Set("target_org", org)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.handleToken(rec, req)
	return rec
}

func (s *Server) decodeMinted(t *testing.T, rec *httptest.ResponseRecorder) jwt.MapClaims {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("no access_token in response: %s", rec.Body.String())
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(at, claims, func(*jwt.Token) (interface{}, error) {
		return &s.privateKey.PublicKey, nil
	}); err != nil {
		t.Fatalf("parse minted: %v", err)
	}
	return claims
}

// platform-admin drops into a target org: sub preserved, org_id retargeted,
// role stamped superadmin, platform carried, act delegation recorded.
func TestTokenExchange_MintsDelegatedToken(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{
		RequireClaim: exNS + "platform",
		CarryClaims:  []string{exNS + "platform"},
		SetClaims:    map[string]string{exNS + "role": "superadmin"},
		Actor:        true,
	})
	subject := srv.signSubject(t, jwt.MapClaims{
		"sub":             "auth0|admin",
		"org_id":          "org_1",
		exNS + "role":     "user",
		exNS + "platform": "admin",
	})

	rec := doExchange(t, srv, subject, "org_2")
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	c := srv.decodeMinted(t, rec)

	if c["sub"] != "auth0|admin" {
		t.Errorf("sub: got %v, want auth0|admin", c["sub"])
	}
	if c["org_id"] != "org_2" {
		t.Errorf("org_id: got %v, want org_2", c["org_id"])
	}
	if c[exNS+"role"] != "superadmin" {
		t.Errorf("role: got %v, want superadmin", c[exNS+"role"])
	}
	if c[exNS+"platform"] != "admin" {
		t.Errorf("platform: got %v, want admin (carried)", c[exNS+"platform"])
	}
	act, ok := c["act"].(map[string]any)
	if !ok || act["sub"] != "auth0|admin" {
		t.Errorf("act: got %v, want {sub: auth0|admin}", c["act"])
	}
}

func TestTokenExchange_DeniedWithoutRequiredClaim(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{
		RequireClaim: exNS + "platform",
		SetClaims:    map[string]string{exNS + "role": "superadmin"},
	})
	// Subject is a normal user, no platform claim.
	subject := srv.signSubject(t, jwt.MapClaims{"sub": "auth0|user", "org_id": "org_1"})

	rec := doExchange(t, srv, subject, "org_2")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-platform subject, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestTokenExchange_UnknownTargetOrg(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{RequireClaim: exNS + "platform"})
	subject := srv.signSubject(t, jwt.MapClaims{"sub": "auth0|admin", exNS + "platform": "admin"})

	rec := doExchange(t, srv, subject, "org_nonexistent")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown org, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestTokenExchange_RejectsGarbageSubjectToken(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{RequireClaim: exNS + "platform"})
	rec := doExchange(t, srv, "not-a-jwt", "org_2")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for garbage subject_token, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestTokenExchange_RejectsWrongSubjectTokenType(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{RequireClaim: exNS + "platform"})
	subject := srv.signSubject(t, jwt.MapClaims{"sub": "auth0|admin", exNS + "platform": "admin"})

	form := url.Values{}
	form.Set("grant_type", tokenExchangeGrantType)
	form.Set("subject_token", subject)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token") // reserved / no profile
	form.Set("target_org", "org_2")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.handleToken(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unmatched subject_token_type, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// A consumer whose exchange crosses into an organization the caller does not
// belong to cannot use the native org_id claim: real Auth0 only sets it through
// setOrganization, which refuses a non-member. Minting it here regardless let
// such a flow pass locally and fail against Auth0, so the claim is configurable.
func TestTokenExchangeMintsTheConfiguredOrgClaim(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{
		RequireClaim: exNS + "platform",
		OrgClaim:     exNS + "org_id",
		Actor:        true,
	})

	subject := srv.signSubject(t, jwt.MapClaims{
		"sub":             "auth0|admin",
		exNS + "platform": "admin",
	})
	rec := doExchange(t, srv, subject, "org_2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	claims := srv.decodeMinted(t, rec)

	if claims[exNS+"org_id"] != "org_2" {
		t.Fatalf("namespaced org claim = %v, want org_2", claims[exNS+"org_id"])
	}
	// The native claim must be absent: Auth0 cannot produce it for a non-member,
	// so minting it would hide exactly the failure this models.
	if v, ok := claims["org_id"]; ok {
		t.Fatalf("minted a native org_id (%v) that real Auth0 would refuse", v)
	}
}

// Unset keeps the previous behaviour, for a consumer whose caller is a member.
func TestTokenExchangeDefaultsToTheNativeOrgClaim(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{
		RequireClaim: exNS + "platform",
		Actor:        true,
	})

	subject := srv.signSubject(t, jwt.MapClaims{
		"sub":             "auth0|admin",
		exNS + "platform": "admin",
	})
	rec := doExchange(t, srv, subject, "org_2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if claims := srv.decodeMinted(t, rec); claims["org_id"] != "org_2" {
		t.Fatalf("native org_id = %v, want org_2", claims["org_id"])
	}
}

// An overlay must not reach the organization claim. Carrying the subject's own
// org_id scopes the token to where the caller came from rather than where it
// asked to go, and in custom-org mode it restores the native claim real Auth0
// cannot issue for a non-member.
func TestTokenExchangeOverlaysCannotReachTheOrgClaim(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{
		RequireClaim: exNS + "platform",
		OrgClaim:     exNS + "org_id",
		// Both overlays aimed at the organization, from either direction.
		CarryClaims: []string{"org_id", exNS + "platform"},
		SetClaims:   map[string]string{exNS + "org_id": "org_hijacked"},
		Actor:       true,
	})

	subject := srv.signSubject(t, jwt.MapClaims{
		"sub":             "auth0|admin",
		"org_id":          "org_1",
		exNS + "platform": "admin",
	})
	rec := doExchange(t, srv, subject, "org_2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	claims := srv.decodeMinted(t, rec)

	if claims[exNS+"org_id"] != "org_2" {
		t.Fatalf("org claim = %v, want the requested target org_2", claims[exNS+"org_id"])
	}
	if v, ok := claims["org_id"]; ok {
		t.Fatalf("an overlay restored the native org_id (%v)", v)
	}
	// Unrelated overlays still apply.
	if claims[exNS+"platform"] != "admin" {
		t.Fatalf("carry_claims dropped an unrelated claim: %v", claims[exNS+"platform"])
	}
}
