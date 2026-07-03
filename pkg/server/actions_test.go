package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/46labs/auth0/pkg/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

func TestResolveTemplate_LiteralPassthrough(t *testing.T) {
	got, ok := resolveTemplate("plain-string", map[string]any{})
	if !ok || got != "plain-string" {
		t.Fatalf("literal: got (%q, %v), want (%q, true)", got, ok, "plain-string")
	}
}

func TestResolveTemplate_SingleReference(t *testing.T) {
	ctx := map[string]any{
		"user": map[string]any{"email": "a@b.test"},
	}
	got, ok := resolveTemplate("${user.email}", ctx)
	if !ok || got != "a@b.test" {
		t.Fatalf("single ref: got (%q, %v)", got, ok)
	}
}

func TestResolveTemplate_MultipleReferences(t *testing.T) {
	ctx := map[string]any{
		"user": map[string]any{"name": "Alice", "email": "a@b.test"},
	}
	got, ok := resolveTemplate("${user.name} <${user.email}>", ctx)
	if !ok || got != "Alice <a@b.test>" {
		t.Fatalf("multi ref: got (%q, %v)", got, ok)
	}
}

func TestResolveTemplate_SkipOnEmpty(t *testing.T) {
	ctx := map[string]any{
		"user": map[string]any{"phone_number": ""},
	}
	got, ok := resolveTemplate("${user.phone_number}", ctx)
	if ok {
		t.Fatalf("expected skip on empty, got (%q, true)", got)
	}
}

func TestResolveTemplate_MissingPath(t *testing.T) {
	ctx := map[string]any{
		"user": map[string]any{"email": "a@b.test"},
	}
	got, ok := resolveTemplate("${user.does_not_exist}", ctx)
	if ok {
		t.Fatalf("expected skip on missing path, got (%q, true)", got)
	}
}

func TestResolveTemplate_MissingIntermediateBranch(t *testing.T) {
	ctx := map[string]any{
		"user": map[string]any{},
	}
	_, ok := resolveTemplate("${user.app_metadata.role}", ctx)
	if ok {
		t.Fatalf("expected skip when intermediate map missing")
	}
}

func TestLookupPath_NestedMaps(t *testing.T) {
	ctx := map[string]any{
		"user": map[string]any{
			"app_metadata": map[string]any{"role": "admin"},
		},
	}
	if got := lookupPath(ctx, "user.app_metadata.role"); got != "admin" {
		t.Fatalf("got %q, want admin", got)
	}
}

func TestLookupPath_NonStringStringification(t *testing.T) {
	ctx := map[string]any{
		"count": 42,
	}
	if got := lookupPath(ctx, "count"); got != "42" {
		t.Fatalf("got %q, want 42", got)
	}
}

// minimalServer constructs a Server with just enough config for action tests.
// Avoids the heavy setupTestServer scaffolding when only action wiring is
// under test.
func minimalServer(t *testing.T, pl *config.PostLoginAction) *Server {
	t.Helper()
	cfg := &config.Config{
		Issuer:   "https://auth.example.test/",
		Audience: "https://api.example.test",
		Users: []config.User{{
			ID:    "auth0|u1",
			Email: "u1@example.test",
			Phone: "+15555550100",
			Name:  "User One",
			AppMetadata: config.AppMetadata{
				config.AppMetaTenantID: "org_1",
				config.AppMetaRole:     "admin",
			},
		}},
		Organizations: []config.Organization{{ID: "org_1", Name: "org-one"}},
		Members: []config.OrganizationMember{
			{UserID: "auth0|u1", OrgID: "org_1", Role: "owner"},
		},
		Clients: []config.Client{{ClientID: "spa_app", Name: "SPA App"}},
		Actions: config.Actions{PostLogin: pl},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func TestApplyPostLogin_NilIsNoop(t *testing.T) {
	srv := minimalServer(t, nil)
	user := srv.users["auth0|u1"]

	idClaims := jwt.MapClaims{"sub": user.ID}
	accessClaims := jwt.MapClaims{"sub": user.ID}
	srv.applyPostLogin(user, srv.clients["spa_app"], idClaims, accessClaims)

	if len(idClaims) != 1 || len(accessClaims) != 1 {
		t.Fatalf("nil PostLogin must not mutate claims: id=%v access=%v", idClaims, accessClaims)
	}
}

func TestApplyPostLogin_NamespacedAndRawClaims(t *testing.T) {
	srv := minimalServer(t, &config.PostLoginAction{
		IDTokenClaims: map[string]string{
			"role": "${user.app_metadata.role}",
		},
		IDTokenRawClaims: map[string]string{
			"org_id": "${user.app_metadata.tenant_id}",
		},
		AccessTokenClaims: map[string]string{
			"role": "${authorization.role}",
		},
		AccessTokenRawClaims: map[string]string{
			"org_id": "${user.app_metadata.tenant_id}",
		},
	})
	user := srv.users["auth0|u1"]
	idClaims := jwt.MapClaims{}
	accessClaims := jwt.MapClaims{}

	srv.applyPostLogin(user, srv.clients["spa_app"], idClaims, accessClaims)

	ns := "https://auth.example.test/"
	if idClaims[ns+"role"] != "admin" {
		t.Errorf("id_token namespaced role: got %v", idClaims[ns+"role"])
	}
	if idClaims["org_id"] != "org_1" {
		t.Errorf("id_token raw org_id: got %v", idClaims["org_id"])
	}
	if accessClaims[ns+"role"] != "owner" {
		t.Errorf("access_token namespaced role from authorization.role: got %v", accessClaims[ns+"role"])
	}
	if accessClaims["org_id"] != "org_1" {
		t.Errorf("access_token raw org_id: got %v", accessClaims["org_id"])
	}
}

func TestApplyPostLogin_SkipsClaimsWithEmptySource(t *testing.T) {
	srv := minimalServer(t, &config.PostLoginAction{
		IDTokenClaims: map[string]string{
			"role":         "${user.app_metadata.role}",
			"phone_number": "${user.phone_number}",
			"missing":      "${user.user_metadata.absent}",
		},
	})
	// Wipe phone so the phone claim must be skipped.
	srv.users["auth0|u1"].Phone = ""

	idClaims := jwt.MapClaims{}
	srv.applyPostLogin(srv.users["auth0|u1"], srv.clients["spa_app"], idClaims, jwt.MapClaims{})

	ns := "https://auth.example.test/"
	if _, ok := idClaims[ns+"phone_number"]; ok {
		t.Errorf("expected phone_number to be skipped when source empty")
	}
	if _, ok := idClaims[ns+"missing"]; ok {
		t.Errorf("expected missing claim to be skipped")
	}
	if idClaims[ns+"role"] != "admin" {
		t.Errorf("role claim should still be set: got %v", idClaims[ns+"role"])
	}
}

func TestApplyPostLogin_AuthorizationContextFromMembers(t *testing.T) {
	srv := minimalServer(t, &config.PostLoginAction{
		AccessTokenClaims: map[string]string{
			"role":   "${authorization.role}",
			"org_id": "${authorization.org_id}",
		},
	})

	user := srv.users["auth0|u1"]
	accessClaims := jwt.MapClaims{}
	srv.applyPostLogin(user, srv.clients["spa_app"], jwt.MapClaims{}, accessClaims)

	ns := "https://auth.example.test/"
	if accessClaims[ns+"role"] != "owner" {
		t.Errorf("authorization.role: got %v, want owner", accessClaims[ns+"role"])
	}
	if accessClaims[ns+"org_id"] != "org_1" {
		t.Errorf("authorization.org_id: got %v, want org_1", accessClaims[ns+"org_id"])
	}
}

func TestApplyPostLogin_AuthorizationEmptyWhenNoMembership(t *testing.T) {
	srv := minimalServer(t, &config.PostLoginAction{
		AccessTokenClaims: map[string]string{
			"role": "${authorization.role}",
		},
	})
	delete(srv.users["auth0|u1"].AppMetadata, config.AppMetaTenantID) // user belongs to no org

	accessClaims := jwt.MapClaims{}
	srv.applyPostLogin(srv.users["auth0|u1"], srv.clients["spa_app"], jwt.MapClaims{}, accessClaims)

	ns := "https://auth.example.test/"
	if _, ok := accessClaims[ns+"role"]; ok {
		t.Errorf("expected authorization.role to be empty (skipped) when user has no tenant")
	}
}

func TestApplyPostLogin_LiteralClaims(t *testing.T) {
	srv := minimalServer(t, &config.PostLoginAction{
		IDTokenRawClaims: map[string]string{
			"environment": "development",
		},
	})

	idClaims := jwt.MapClaims{}
	srv.applyPostLogin(srv.users["auth0|u1"], srv.clients["spa_app"], idClaims, jwt.MapClaims{})

	if idClaims["environment"] != "development" {
		t.Errorf("literal raw claim: got %v", idClaims["environment"])
	}
}

func TestApplyPostLogin_ClientContext(t *testing.T) {
	srv := minimalServer(t, &config.PostLoginAction{
		AccessTokenClaims: map[string]string{
			"client_name": "${client.name}",
		},
	})

	accessClaims := jwt.MapClaims{}
	srv.applyPostLogin(srv.users["auth0|u1"], srv.clients["spa_app"], jwt.MapClaims{}, accessClaims)

	ns := "https://auth.example.test/"
	if accessClaims[ns+"client_name"] != "SPA App" {
		t.Errorf("client.name: got %v", accessClaims[ns+"client_name"])
	}
}

// TestPostLoginAction_AuthCodeFlow_E2E exercises the full authorization_code
// flow with a configured post_login action and verifies the resulting id_token
// claims via the OIDC verifier, mirroring how SDKs consume the tokens.
func TestPostLoginAction_AuthCodeFlow_E2E(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	srv.cfg.Actions = config.Actions{
		PostLogin: &config.PostLoginAction{
			IDTokenClaims: map[string]string{
				"role":         "${user.app_metadata.role}",
				"phone_number": "${user.phone_number}",
			},
			AccessTokenClaims: map[string]string{
				"role":         "${authorization.role}",
				"phone_number": "${user.phone_number}",
			},
		},
	}

	redirectURI := "http://localhost:3000/callback"
	clientID := "test_client_actions"
	phone := "+14155551234"

	codeVerifier, codeChallenge := generatePKCE()

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&code_challenge=%s&code_challenge_method=S256",
		ts.URL, clientID, url.QueryEscape(redirectURI), codeChallenge)
	resp, err := httpClient.Get(authURL)
	if err != nil {
		t.Fatalf("auth page: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	sessionID := regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(string(body))[1]

	resp2, err := httpClient.PostForm(ts.URL+"/authorize", url.Values{
		"session_id": {sessionID},
		"phone":      {phone},
		"code":       {"123456"},
	})
	if err != nil {
		t.Fatalf("submit code: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	location := resp2.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	authCode := redirectURL.Query().Get("code")

	resp3, err := httpClient.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	defer func() { _ = resp3.Body.Close() }()

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp3.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token resp: %v", err)
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, srv.cfg.Issuer)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idTok, err := verifier.Verify(ctx, tokenResp["id_token"].(string))
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}

	var idClaims map[string]any
	if err := idTok.Claims(&idClaims); err != nil {
		t.Fatalf("decode id claims: %v", err)
	}

	ns := strings.TrimSuffix(srv.cfg.Issuer, "/") + "/"
	if idClaims[ns+"role"] != "admin" {
		t.Errorf("id_token %srole = %v, want admin", ns, idClaims[ns+"role"])
	}
	if idClaims[ns+"phone_number"] != phone {
		t.Errorf("id_token %sphone_number = %v, want %s", ns, idClaims[ns+"phone_number"], phone)
	}

	accessParsed, _, err := new(jwt.Parser).ParseUnverified(tokenResp["access_token"].(string), jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	accessClaims := accessParsed.Claims.(jwt.MapClaims)
	if accessClaims[ns+"role"] != "admin" {
		// authorization.role for test_user_1 is "admin" from members config
		t.Errorf("access_token %srole = %v, want admin", ns, accessClaims[ns+"role"])
	}
	if accessClaims[ns+"phone_number"] != phone {
		t.Errorf("access_token %sphone_number = %v, want %s", ns, accessClaims[ns+"phone_number"], phone)
	}
}

