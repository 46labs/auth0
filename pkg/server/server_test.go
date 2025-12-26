package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/coreos/go-oidc/v3/oidc"
)

func setupTestServer(t *testing.T) (*Server, *httptest.Server) {
	cfg := &config.Config{
		Issuer:      "http://localhost:4646/",
		Audience:    "http://localhost:3000",
		Port:        4646,
		CORSOrigins: []string{"*"},
		Users: []config.User{
			{
				ID:    "test_user_1",
				Phone: "+14155551234",
				Email: "test@46labs.test",
				Name:  "Test User",
			},
		},
		Branding: config.Branding{
			ServiceName:  "Test Auth",
			PrimaryColor: "#3b82f6",
			Title:        "Sign In",
			Subtitle:     "Enter your phone number",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", srv.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", srv.handleJWKS)
	mux.HandleFunc("/authorize", srv.handleAuthorize)
	mux.HandleFunc("/oauth/token", srv.handleToken)
	mux.HandleFunc("/userinfo", srv.handleUserInfo)
	mux.HandleFunc("/v2/logout", srv.handleLogout)

	ts := httptest.NewServer(mux)
	srv.cfg.Issuer = ts.URL + "/"

	return srv, ts
}

func generatePKCE() (string, string) {
	verifier := make([]byte, 32)
	_, _ = io.ReadFull(io.Reader(strings.NewReader("test_verifier_for_pkce_flow_testing")), verifier)
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifier)

	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return codeVerifier, codeChallenge
}

func TestOIDCDiscovery(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	var discovery map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode discovery: %v", err)
	}

	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"userinfo_endpoint",
	}

	for _, field := range requiredFields {
		if discovery[field] == nil {
			t.Errorf("Missing required field: %s", field)
		}
	}

	t.Log("OIDC discovery valid")
}

func TestCompleteOAuth2PKCEFlow(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	redirectURI := "http://localhost:3000/callback"
	clientID := "test_client"
	phone := "+14155551234"
	smsCode := "123456"

	codeVerifier, codeChallenge := generatePKCE()
	state := "test_state_" + fmt.Sprint(time.Now().Unix())

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Log("Step 1: Get authorization page")
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256",
		ts.URL, clientID, url.QueryEscape(redirectURI), state, codeChallenge)

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to get auth page: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	re := regexp.MustCompile(`value="([^"]*)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		t.Fatalf("Could not find session ID")
	}
	sessionID := matches[1]

	t.Log("Step 2: Submit phone + verification code")
	formData := url.Values{
		"session_id": {sessionID},
		"phone":      {phone},
		"code":       {smsCode},
	}

	resp2, err := client.PostForm(ts.URL+"/authorize", formData)
	if err != nil {
		t.Fatalf("Failed to submit code: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != 302 {
		t.Fatalf("Expected 302, got %d", resp2.StatusCode)
	}

	location := resp2.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	authCode := redirectURL.Query().Get("code")

	if authCode == "" {
		t.Fatalf("No authorization code in redirect")
	}

	t.Log("Step 3: Exchange code for tokens")
	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}

	resp3, err := client.PostForm(ts.URL+"/oauth/token", tokenData)
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}
	defer func() { _ = resp3.Body.Close() }()

	if resp3.StatusCode != 200 {
		body, _ := io.ReadAll(resp3.Body)
		t.Fatalf("Token exchange failed: %d - %s", resp3.StatusCode, string(body))
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp3.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResp["access_token"] == nil {
		t.Fatal("Missing access_token")
	}
	if tokenResp["id_token"] == nil {
		t.Fatal("Missing id_token")
	}

	t.Log("Step 4: Validate ID token")
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, srv.cfg.Issuer)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, tokenResp["id_token"].(string))
	if err != nil {
		t.Fatalf("ID token verification failed: %v", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("Failed to extract claims: %v", err)
	}

	requiredClaims := []string{"sub", "email", "name", "phone_number"}
	for _, claim := range requiredClaims {
		if claims[claim] == nil {
			t.Errorf("Missing claim: %s", claim)
		}
	}

	t.Log("Complete OAuth2 PKCE flow passed")
}

func TestLogoutEndpoint(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	returnTo := "http://localhost:3000"

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	logoutURL := fmt.Sprintf("%s/v2/logout?returnTo=%s", ts.URL, url.QueryEscape(returnTo))
	resp, err := client.Get(logoutURL)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 302 {
		t.Fatalf("Expected 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != returnTo {
		t.Errorf("Expected redirect to %s, got %s", returnTo, location)
	}

	t.Log("Logout endpoint passed")
}

func TestCORSHeaders(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	tests := []struct {
		endpoint string
		method   string
	}{
		{"/.well-known/openid-configuration", "GET"},
		{"/.well-known/jwks.json", "GET"},
		{"/oauth/token", "OPTIONS"},
	}

	for _, tt := range tests {
		req, _ := http.NewRequest(tt.method, ts.URL+tt.endpoint, nil)
		req.Header.Set("Origin", "http://localhost:3000")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		corsHeader := resp.Header.Get("Access-Control-Allow-Origin")
		if corsHeader == "" {
			t.Errorf("%s %s missing CORS header", tt.method, tt.endpoint)
		}
	}

	t.Log("CORS headers passed")
}

func TestUserInfoEndpoint(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	accessToken, _ := srv.SignToken(map[string]interface{}{
		"sub":          "test_user_1",
		"email":        "test@46labs.test",
		"name":         "Test User",
		"phone_number": "+14155551234",
		"iss":          srv.cfg.Issuer,
		"aud":          srv.cfg.Audience,
		"exp":          time.Now().Add(time.Hour).Unix(),
		"iat":          time.Now().Unix(),
	})

	req, _ := http.NewRequest("GET", ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("UserInfo request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		t.Fatalf("Failed to decode userinfo: %v", err)
	}

	if userInfo["sub"] != "test_user_1" {
		t.Errorf("Expected sub=test_user_1, got %v", userInfo["sub"])
	}

	t.Log("UserInfo endpoint passed")
}

func TestInvalidAuthorizationCode(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	tokenData := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {"test_client"},
		"code":         {"invalid_code_12345"},
		"redirect_uri": {"http://localhost:3000/callback"},
	}

	resp, err := http.PostForm(ts.URL+"/oauth/token", tokenData)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 200 {
		t.Fatal("Expected error for invalid code")
	}

	t.Log("Invalid code rejected")
}

func TestWrongVerificationCode(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	redirectURI := "http://localhost:3000/callback"
	clientID := "test_client"
	phone := "+14155551234"
	wrongCode := "999999"

	_, codeChallenge := generatePKCE()
	state := "test_state"

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		ts.URL, clientID, url.QueryEscape(redirectURI), state, codeChallenge)

	resp, _ := client.Get(authURL)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	re := regexp.MustCompile(`value="([^"]*)"`)
	matches := re.FindStringSubmatch(string(body))
	sessionID := matches[1]

	formData := url.Values{
		"session_id": {sessionID},
		"phone":      {phone},
		"code":       {wrongCode},
	}

	resp2, err := client.PostForm(ts.URL+"/authorize", formData)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode == 302 {
		t.Fatal("Expected error for wrong code")
	}

	t.Log("Wrong verification code rejected")
}

func TestMissingBearerToken(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/userinfo", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 401 {
		t.Fatalf("Expected 401, got %d", resp.StatusCode)
	}

	t.Log("Missing token rejected")
}

func TestInvalidBearerToken(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid_token_xyz")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 401 {
		t.Fatalf("Expected 401, got %d", resp.StatusCode)
	}

	t.Log("Invalid token rejected")
}
