package server

// IMPORTANT: ALWAYS USE THE AUTH0 SDK
//
// All Management API tests MUST use the official github.com/auth0/go-auth0/management SDK
// to ensure compatibility and parity with the real Auth0 API.
//
// Do NOT use raw HTTP requests for Management API testing.
// OAuth flow tests may use raw HTTP as they test the authentication flow itself.

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
	"github.com/auth0/go-auth0/management"
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
				ID:            "test_user_1",
				Phone:         "+14155551234",
				Email:         "test@example.test",
				Name:          "Test User",
				EmailVerified: true,
				Identities: []config.UserIdentity{
					{
						Connection: "sms",
						Provider:   "sms",
						UserID:     "test_user_1",
						IsSocial:   false,
					},
				},
				AppMetadata: config.AppMetadata{
					TenantID: "org_test",
					Role:     "admin",
				},
				Organizations: []string{"org_test"},
			},
			{
				ID:            "test_user_2",
				Email:         "email@example.test",
				Name:          "Email User",
				EmailVerified: true,
				Identities: []config.UserIdentity{
					{
						Connection: "email",
						Provider:   "email",
						UserID:     "test_user_2",
						IsSocial:   false,
					},
				},
				AppMetadata: config.AppMetadata{
					TenantID: "org_test",
					Role:     "member",
				},
				Organizations: []string{"org_test"},
			},
		},
		Organizations: []config.Organization{
			{
				ID:          "org_test",
				Name:        "test-org",
				DisplayName: "Test Organization",
			},
		},
		Connections: []config.Connection{
			{
				ID:             "con_sms",
				Name:           "sms",
				Strategy:       "sms",
				DisplayName:    "SMS",
				Organizations:  []string{"org_test"},
				EnabledClients: []string{"*"},
			},
			{
				ID:             "con_email",
				Name:           "email",
				Strategy:       "email",
				DisplayName:    "Email",
				Organizations:  []string{"org_test"},
				EnabledClients: []string{"*"},
			},
		},
		Members: []config.OrganizationMember{
			{UserID: "test_user_1", OrgID: "org_test", Role: "admin"},
			{UserID: "test_user_2", OrgID: "org_test", Role: "member"},
		},
		Branding: config.Branding{
			ServiceName:  "Test Auth",
			PrimaryColor: "#3b82f6",
			Title:        "Sign In",
			Subtitle:     "Enter your identifier",
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
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

func TestEmailAuthentication(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	redirectURI := "http://localhost:3000/callback"
	clientID := "test_client"
	email := "email@example.test"
	code := "123456"

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
		"identifier": {email},
		"code":       {code},
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

	user := srv.findUser(email)
	if user == nil {
		t.Fatal("User not found by email")
	}

	if user.Email != email {
		t.Errorf("Expected email %s, got %s", email, user.Email)
	}

	t.Log("Email authentication passed")
}

func TestCustomClaimsInToken(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	redirectURI := "http://localhost:3000/callback"
	clientID := "test_client"
	phone := "+14155551234"
	smsCode := "123456"

	codeVerifier, codeChallenge := generatePKCE()
	state := "test_state"

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256",
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
		"code":       {smsCode},
	}

	resp2, _ := client.PostForm(ts.URL+"/authorize", formData)
	location := resp2.Header.Get("Location")
	_ = resp2.Body.Close()

	redirectURL, _ := url.Parse(location)
	authCode := redirectURL.Query().Get("code")

	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}

	resp3, _ := client.PostForm(ts.URL+"/oauth/token", tokenData)
	defer func() { _ = resp3.Body.Close() }()

	var tokenResp map[string]interface{}
	_ = json.NewDecoder(resp3.Body).Decode(&tokenResp)

	ctx := context.Background()
	provider, _ := oidc.NewProvider(ctx, srv.cfg.Issuer)
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, _ := verifier.Verify(ctx, tokenResp["id_token"].(string))

	var claims map[string]interface{}
	_ = idToken.Claims(&claims)

	expectedClaims := map[string]string{
		srv.cfg.Issuer + "tenant_id": "org_test",
		srv.cfg.Issuer + "role":      "admin",
	}

	for claimKey, expectedValue := range expectedClaims {
		if claims[claimKey] == nil {
			t.Errorf("Missing custom claim: %s", claimKey)
		} else if claims[claimKey].(string) != expectedValue {
			t.Errorf("Expected %s=%s, got %s", claimKey, expectedValue, claims[claimKey])
		}
	}

	t.Log("Custom claims verification passed")
}

func TestManagementAPIOrganizations(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	// Create management client using Auth0 SDK
	m, err := management.New(
		ts.URL,
		management.WithStaticToken("mock_token"),
		management.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("Failed to create management client: %v", err)
	}

	t.Run("ListOrganizations", func(t *testing.T) {
		orgs, err := m.Organization.List(context.Background())
		if err != nil {
			t.Fatalf("Failed to list organizations: %v", err)
		}

		if len(orgs.Organizations) == 0 {
			t.Error("Expected at least one organization")
		}

		t.Logf("Found %d organizations via SDK", len(orgs.Organizations))
	})

	t.Run("GetOrganization", func(t *testing.T) {
		org, err := m.Organization.Read(context.Background(), "org_test")
		if err != nil {
			t.Fatalf("Failed to get organization: %v", err)
		}

		if org.GetID() != "org_test" {
			t.Errorf("Expected org_test, got %s", org.GetID())
		}

		t.Logf("Read organization: %s via SDK", org.GetID())
	})

	t.Run("CreateOrganization", func(t *testing.T) {
		name := "new-org"
		displayName := "New Org"
		newOrg := &management.Organization{
			Name:        &name,
			DisplayName: &displayName,
		}

		err := m.Organization.Create(context.Background(), newOrg)
		if err != nil {
			t.Fatalf("Failed to create organization: %v", err)
		}

		if newOrg.GetID() == "" {
			t.Error("Expected generated ID")
		}

		t.Logf("Created organization: %s via SDK", newOrg.GetID())
	})
}

func TestManagementAPIUsers(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Create management client using Auth0 SDK
	m, err := management.New(
		ts.URL,
		management.WithStaticToken("mock_token"),
		management.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("Failed to create management client: %v", err)
	}

	t.Run("GetUser", func(t *testing.T) {
		user, err := m.User.Read(context.Background(), "test_user_1")
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		if user.GetID() != "test_user_1" {
			t.Errorf("Expected test_user_1, got %s", user.GetID())
		}

		t.Logf("Read user: %s via SDK", user.GetID())
	})

	t.Run("UpdateUser", func(t *testing.T) {
		appMeta := map[string]interface{}{
			"tenant_id": "org_updated",
			"role":      "member",
		}
		updates := &management.User{
			AppMetadata: &appMeta,
		}

		err := m.User.Update(context.Background(), "test_user_1", updates)
		if err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		// Verify the update
		user := srv.getUserByID("test_user_1")
		if user.AppMetadata.TenantID != "org_updated" {
			t.Errorf("Expected tenant_id=org_updated, got %s", user.AppMetadata.TenantID)
		}
		if user.AppMetadata.Role != "member" {
			t.Errorf("Expected role=member, got %s", user.AppMetadata.Role)
		}

		t.Log("Updated user metadata via SDK")
	})

	t.Run("BlockUser", func(t *testing.T) {
		blocked := true
		updates := &management.User{
			Blocked: &blocked,
		}

		err := m.User.Update(context.Background(), "test_user_1", updates)
		if err != nil {
			t.Fatalf("Failed to block user: %v", err)
		}

		user := srv.getUserByID("test_user_1")
		if user.Blocked == nil {
			t.Errorf("Expected blocked to be set, got nil")
		} else if !*user.Blocked {
			t.Errorf("Expected blocked=true, got false")
		}

		t.Log("Blocked user via SDK")
	})

	t.Run("UnblockUser", func(t *testing.T) {
		blocked := false
		updates := &management.User{
			Blocked: &blocked,
		}

		err := m.User.Update(context.Background(), "test_user_1", updates)
		if err != nil {
			t.Fatalf("Failed to unblock user: %v", err)
		}

		user := srv.getUserByID("test_user_1")
		if user.Blocked == nil {
			t.Errorf("Expected blocked to be set, got nil")
		} else if *user.Blocked {
			t.Errorf("Expected blocked=false, got true")
		}

		t.Log("Unblocked user via SDK")
	})
}

func TestLoginHintParameter(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	redirectURI := "http://localhost:3000/callback"
	clientID := "test_client"

	_, codeChallenge := generatePKCE()
	state := "test_state"

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Log("Test 1: Verify login_hint with email pre-fills the identifier field")
	emailHint := "user@domain.com"
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256&login_hint=%s",
		ts.URL, clientID, url.QueryEscape(redirectURI), state, codeChallenge, url.QueryEscape(emailHint))

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to get auth page: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify the login_hint value appears in the identifier input field
	expectedValue := fmt.Sprintf(`value="%s"`, emailHint)
	if !strings.Contains(bodyStr, expectedValue) {
		t.Errorf("Expected login form to contain pre-filled value '%s'", emailHint)
	}

	t.Log("Test 2: Verify login_hint with phone number pre-fills the identifier field")
	phoneHint := "+14695551212"
	authURL2 := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256&login_hint=%s",
		ts.URL, clientID, url.QueryEscape(redirectURI), state, codeChallenge, url.QueryEscape(phoneHint))

	resp2, err := client.Get(authURL2)
	if err != nil {
		t.Fatalf("Failed to get auth page: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	body2, _ := io.ReadAll(resp2.Body)
	bodyStr2 := string(body2)

	// Find what value is actually in the field
	// Note: HTML templates escape + as &#43; which is correct security behavior
	rePhone := regexp.MustCompile(`name="identifier"[^>]*value="([^"]*)"`)
	if matches := rePhone.FindStringSubmatch(bodyStr2); len(matches) > 1 {
		actualValue := matches[1]
		// The + should be HTML-escaped to &#43;
		expectedEscaped := "&#43;14695551212"
		if actualValue != expectedEscaped {
			t.Errorf("Expected HTML-escaped value '%s' but got '%s'", expectedEscaped, actualValue)
		}
		t.Logf("Phone number correctly pre-filled and HTML-escaped: %s", actualValue)
	} else {
		t.Error("Could not find value attribute in identifier field")
	}

	t.Log("Test 3: Verify form works without login_hint")
	authURLNoHint := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		ts.URL, clientID, url.QueryEscape(redirectURI), state, codeChallenge)

	resp3, err := client.Get(authURLNoHint)
	if err != nil {
		t.Fatalf("Failed to get auth page without login_hint: %v", err)
	}
	defer func() { _ = resp3.Body.Close() }()

	body3, _ := io.ReadAll(resp3.Body)
	bodyStr3 := string(body3)

	// Verify identifier field exists with placeholder but no value
	if !strings.Contains(bodyStr3, `name="identifier"`) {
		t.Error("Expected identifier field to exist in form")
	}
	if strings.Contains(bodyStr3, `placeholder="Email or SMS"`) {
		t.Log("Placeholder text correct")
	}
	// Should not have a value attribute when no login_hint
	re := regexp.MustCompile(`name="identifier"[^>]*value=`)
	if re.MatchString(bodyStr3) {
		t.Error("Expected identifier field to NOT have a value when login_hint is not provided")
	}

	t.Log("login_hint parameter test passed")
}

func TestRefreshTokenFlow(t *testing.T) {
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
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email+offline_access&state=%s&code_challenge=%s&code_challenge_method=S256",
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

	t.Log("Step 3: Exchange code for tokens with offline_access scope")
	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
		"scope":         {"openid profile email offline_access"},
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
	if tokenResp["refresh_token"] == nil {
		t.Fatal("Missing refresh_token")
	}

	refreshToken := tokenResp["refresh_token"].(string)
	t.Logf("Got refresh token: %s", refreshToken)

	t.Log("Step 4: Use refresh token to get new tokens")
	refreshData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	}

	resp4, err := client.PostForm(ts.URL+"/oauth/token", refreshData)
	if err != nil {
		t.Fatalf("Refresh token exchange failed: %v", err)
	}
	defer func() { _ = resp4.Body.Close() }()

	if resp4.StatusCode != 200 {
		body, _ := io.ReadAll(resp4.Body)
		t.Fatalf("Refresh token exchange failed: %d - %s", resp4.StatusCode, string(body))
	}

	var refreshResp map[string]interface{}
	if err := json.NewDecoder(resp4.Body).Decode(&refreshResp); err != nil {
		t.Fatalf("Failed to decode refresh response: %v", err)
	}

	if refreshResp["access_token"] == nil {
		t.Fatal("Missing access_token in refresh response")
	}
	if refreshResp["id_token"] == nil {
		t.Fatal("Missing id_token in refresh response")
	}
	if refreshResp["refresh_token"] == nil {
		t.Fatal("Missing refresh_token in refresh response")
	}

	t.Log("Step 5: Validate new ID token")
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, srv.cfg.Issuer)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, refreshResp["id_token"].(string))
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

	t.Log("Refresh token flow passed")
}

func TestRefreshTokenWithoutOfflineAccess(t *testing.T) {
	_, ts := setupTestServer(t)
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

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256",
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
		"code":       {smsCode},
	}

	resp2, _ := client.PostForm(ts.URL+"/authorize", formData)
	location := resp2.Header.Get("Location")
	_ = resp2.Body.Close()

	redirectURL, _ := url.Parse(location)
	authCode := redirectURL.Query().Get("code")

	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
		"scope":         {"openid profile email"},
	}

	resp3, _ := client.PostForm(ts.URL+"/oauth/token", tokenData)
	defer func() { _ = resp3.Body.Close() }()

	var tokenResp map[string]interface{}
	_ = json.NewDecoder(resp3.Body).Decode(&tokenResp)

	if tokenResp["refresh_token"] != nil {
		t.Error("Should not receive refresh_token without offline_access scope")
	}

	t.Log("Correctly omitted refresh_token without offline_access scope")
}

func TestInvalidRefreshToken(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	clientID := "test_client"
	invalidRefreshToken := "rt_invalid_token_12345"

	refreshData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {invalidRefreshToken},
	}

	resp, err := http.PostForm(ts.URL+"/oauth/token", refreshData)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 200 {
		t.Fatal("Expected error for invalid refresh token")
	}

	var errorResp map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&errorResp)

	if errorResp["error"] != "invalid_grant" {
		t.Errorf("Expected error=invalid_grant, got %v", errorResp["error"])
	}

	t.Log("Invalid refresh token rejected")
}

func TestRefreshTokenPreservesCustomClaims(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	redirectURI := "http://localhost:3000/callback"
	clientID := "test_client"
	phone := "+14155551234"
	smsCode := "123456"

	codeVerifier, codeChallenge := generatePKCE()
	state := "test_state"

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email+offline_access&state=%s&code_challenge=%s&code_challenge_method=S256",
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
		"code":       {smsCode},
	}

	resp2, _ := client.PostForm(ts.URL+"/authorize", formData)
	location := resp2.Header.Get("Location")
	_ = resp2.Body.Close()

	redirectURL, _ := url.Parse(location)
	authCode := redirectURL.Query().Get("code")

	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
		"scope":         {"openid profile email offline_access"},
	}

	resp3, _ := client.PostForm(ts.URL+"/oauth/token", tokenData)
	defer func() { _ = resp3.Body.Close() }()

	var tokenResp map[string]interface{}
	_ = json.NewDecoder(resp3.Body).Decode(&tokenResp)

	refreshToken := tokenResp["refresh_token"].(string)

	// Use refresh token
	refreshData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	}

	resp4, _ := client.PostForm(ts.URL+"/oauth/token", refreshData)
	defer func() { _ = resp4.Body.Close() }()

	var refreshResp map[string]interface{}
	_ = json.NewDecoder(resp4.Body).Decode(&refreshResp)

	// Validate custom claims in new ID token
	ctx := context.Background()
	provider, _ := oidc.NewProvider(ctx, srv.cfg.Issuer)
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, _ := verifier.Verify(ctx, refreshResp["id_token"].(string))

	var claims map[string]interface{}
	_ = idToken.Claims(&claims)

	expectedClaims := map[string]string{
		srv.cfg.Issuer + "tenant_id": "org_test",
		srv.cfg.Issuer + "role":      "admin",
	}

	for claimKey, expectedValue := range expectedClaims {
		if claims[claimKey] == nil {
			t.Errorf("Missing custom claim: %s", claimKey)
		} else if claims[claimKey].(string) != expectedValue {
			t.Errorf("Expected %s=%s, got %s", claimKey, expectedValue, claims[claimKey])
		}
	}

	t.Log("Custom claims preserved in refresh token flow")
}

func TestManagementAPIOrganizationMembers(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Create management client using Auth0 SDK
	m, err := management.New(
		ts.URL,
		management.WithStaticToken("mock_token"),
		management.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("Failed to create management client: %v", err)
	}

	t.Run("ListMembers", func(t *testing.T) {
		membersList, err := m.Organization.Members(context.Background(), "org_test")
		if err != nil {
			t.Fatalf("Failed to list members: %v", err)
		}

		if len(membersList.Members) != 2 {
			t.Errorf("Expected 2 members, got %d", len(membersList.Members))
		}

		t.Logf("Listed %d members via SDK", len(membersList.Members))
	})

	t.Run("AddMembersWithRoles", func(t *testing.T) {
		// First, create a new user to add
		srv.mu.Lock()
		srv.users["test_user_3"] = &config.User{
			ID:            "test_user_3",
			Email:         "newuser@example.test",
			Name:          "New User",
			EmailVerified: true,
			AppMetadata: config.AppMetadata{
				Role: "member",
			},
		}
		srv.mu.Unlock()

		// Step 1: Add member to organization using SDK
		err := m.Organization.AddMembers(context.Background(), "org_test", []string{"test_user_3"})
		if err != nil {
			t.Fatalf("Failed to add member: %v", err)
		}

		// Step 2: Assign role to member using SDK
		roles := []string{"admin"}
		err = m.Organization.AssignMemberRoles(context.Background(), "org_test", "test_user_3", roles)
		if err != nil {
			t.Fatalf("Failed to assign role: %v", err)
		}

		// Verify the member was added with the role
		srv.mu.RLock()
		members := srv.members["org_test"]
		srv.mu.RUnlock()

		found := false
		for _, member := range members {
			if member.UserID == "test_user_3" && member.Role == "admin" {
				found = true
				break
			}
		}

		if !found {
			t.Error("Member was not added to organization with admin role")
		}

		// Verify the user's organizations were updated
		user := srv.getUserByID("test_user_3")
		hasOrg := false
		for _, orgID := range user.Organizations {
			if orgID == "org_test" {
				hasOrg = true
				break
			}
		}

		if !hasOrg {
			t.Error("Organization was not added to user's organizations")
		}

		t.Log("Added member with role via SDK")
	})

	t.Run("AddMembersWithoutRoles", func(t *testing.T) {
		// Create another user
		srv.mu.Lock()
		srv.users["test_user_4"] = &config.User{
			ID:            "test_user_4",
			Email:         "another@example.test",
			Name:          "Another User",
			EmailVerified: true,
			AppMetadata: config.AppMetadata{
				Role: "member",
			},
		}
		srv.mu.Unlock()

		// Add member without assigning role using SDK
		err := m.Organization.AddMembers(context.Background(), "org_test", []string{"test_user_4"})
		if err != nil {
			t.Fatalf("Failed to add member: %v", err)
		}

		// Verify the member was added (role will be empty until assigned)
		srv.mu.RLock()
		members := srv.members["org_test"]
		srv.mu.RUnlock()

		found := false
		for _, member := range members {
			if member.UserID == "test_user_4" {
				found = true
				break
			}
		}

		if !found {
			t.Error("Member was not added")
		}

		t.Log("Added member without role via SDK")
	})

	t.Run("AddMembersToNonexistentOrg", func(t *testing.T) {
		err := m.Organization.AddMembers(context.Background(), "nonexistent", []string{"test_user_1"})
		if err == nil {
			t.Fatal("Expected error when adding to nonexistent org")
		}

		t.Log("Correctly rejected adding to nonexistent org via SDK")
	})

	t.Run("AddMultipleMembers", func(t *testing.T) {
		// Create two more users
		srv.mu.Lock()
		srv.users["test_user_5"] = &config.User{
			ID:            "test_user_5",
			Email:         "user5@example.test",
			Name:          "User Five",
			EmailVerified: true,
		}
		srv.users["test_user_6"] = &config.User{
			ID:            "test_user_6",
			Email:         "user6@example.test",
			Name:          "User Six",
			EmailVerified: true,
		}
		srv.mu.Unlock()

		// Add multiple members using SDK
		err := m.Organization.AddMembers(context.Background(), "org_test", []string{"test_user_5", "test_user_6"})
		if err != nil {
			t.Fatalf("Failed to add members: %v", err)
		}

		// Verify both members were added
		srv.mu.RLock()
		members := srv.members["org_test"]
		srv.mu.RUnlock()

		user5Found := false
		user6Found := false
		for _, member := range members {
			if member.UserID == "test_user_5" {
				user5Found = true
			}
			if member.UserID == "test_user_6" {
				user6Found = true
			}
		}

		if !user5Found {
			t.Error("test_user_5 was not added to organization")
		}
		if !user6Found {
			t.Error("test_user_6 was not added to organization")
		}

		t.Log("Added multiple members via SDK")
	})

	t.Run("AddMemberIdempotent", func(t *testing.T) {
		srv.mu.Lock()
		srv.users["test_user_idempotent"] = &config.User{
			ID:            "test_user_idempotent",
			Email:         "idempotent@example.test",
			Name:          "Idempotent User",
			EmailVerified: true,
		}
		srv.mu.Unlock()

		// Add same member 3 times using SDK
		for i := 0; i < 3; i++ {
			err := m.Organization.AddMembers(context.Background(), "org_test", []string{"test_user_idempotent"})
			if err != nil {
				t.Fatalf("Request %d failed: %v", i+1, err)
			}
		}

		srv.mu.RLock()
		members := srv.members["org_test"]
		srv.mu.RUnlock()

		count := 0
		for _, member := range members {
			if member.UserID == "test_user_idempotent" {
				count++
			}
		}

		if count != 1 {
			t.Errorf("Expected member to appear once, found %d times", count)
		}

		user := srv.getUserByID("test_user_idempotent")
		orgCount := 0
		for _, orgID := range user.Organizations {
			if orgID == "org_test" {
				orgCount++
			}
		}

		if orgCount != 1 {
			t.Errorf("Expected organization to appear once in user's organizations, found %d times", orgCount)
		}

		t.Log("Idempotent add via SDK worked correctly")
	})

	t.Run("AssignRoleUpdatesAppMetadata", func(t *testing.T) {
		// Create a new user without org membership
		srv.mu.Lock()
		srv.users["test_user_jwt"] = &config.User{
			ID:            "test_user_jwt",
			Email:         "jwt@example.test",
			Name:          "JWT Test User",
			EmailVerified: true,
			AppMetadata:   config.AppMetadata{}, // Empty AppMetadata
		}
		srv.mu.Unlock()

		// Add member to organization using SDK
		err := m.Organization.AddMembers(context.Background(), "org_test", []string{"test_user_jwt"})
		if err != nil {
			t.Fatalf("Failed to add member: %v", err)
		}

		// Assign role to member using SDK
		err = m.Organization.AssignMemberRoles(context.Background(), "org_test", "test_user_jwt", []string{"admin"})
		if err != nil {
			t.Fatalf("Failed to assign role: %v", err)
		}

		// Verify AppMetadata was updated with tenant_id and role
		user := srv.getUserByID("test_user_jwt")
		if user.AppMetadata.TenantID != "org_test" {
			t.Errorf("Expected AppMetadata.TenantID='org_test', got '%s'", user.AppMetadata.TenantID)
		}
		if user.AppMetadata.Role != "admin" {
			t.Errorf("Expected AppMetadata.Role='admin', got '%s'", user.AppMetadata.Role)
		}

		t.Log("Role assignment updated AppMetadata via SDK")
	})
}

// TestClientsFromConfig verifies clients can be pre-configured at startup
func TestClientsFromConfig(t *testing.T) {
	cfg := &config.Config{
		Issuer:      "http://localhost:4646/",
		Audience:    "http://localhost:3000",
		Port:        4646,
		CORSOrigins: []string{"*"},
		Users:       []config.User{},
		Organizations: []config.Organization{
			{ID: "org_test", Name: "test-org", DisplayName: "Test Organization"},
		},
		Connections: []config.Connection{
			{ID: "con_sms", Name: "sms", Strategy: "sms"},
			{ID: "con_email", Name: "email", Strategy: "email"},
		},
		Clients: []config.Client{
			{
				ClientID:     "preconfigured_spa",
				Name:         "Preconfigured SPA",
				Description:  "SPA app from config",
				AppType:      "spa",
				Callbacks:    []string{"http://localhost:3000/callback"},
				GrantTypes:   []string{"authorization_code"},
			},
			{
				ClientID:     "preconfigured_m2m",
				Name:         "Preconfigured M2M",
				Description:  "M2M app from config",
				AppType:      "non_interactive",
				ClientSecret: "preconfigured_secret_123",
				GrantTypes:   []string{"client_credentials"},
			},
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	m, err := management.New(
		ts.URL,
		management.WithClientCredentials(
			context.Background(),
			"test_client",
			"test_secret",
		),
		management.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("Failed to create management client: %v", err)
	}

	t.Run("ListPreconfiguredClients", func(t *testing.T) {
		clientList, err := m.Client.List(context.Background())
		if err != nil {
			t.Fatalf("Failed to list clients: %v", err)
		}

		if len(clientList.Clients) != 2 {
			t.Errorf("Expected 2 preconfigured clients, got %d", len(clientList.Clients))
		}

		// Verify SPA client
		var foundSPA, foundM2M bool
		for _, client := range clientList.Clients {
			if client.GetClientID() == "preconfigured_spa" {
				foundSPA = true
				if client.GetName() != "Preconfigured SPA" {
					t.Errorf("Expected name 'Preconfigured SPA', got %s", client.GetName())
				}
				if client.GetAppType() != "spa" {
					t.Errorf("Expected app_type 'spa', got %s", client.GetAppType())
				}
			}
			if client.GetClientID() == "preconfigured_m2m" {
				foundM2M = true
				if client.GetClientSecret() != "preconfigured_secret_123" {
					t.Errorf("Expected preconfigured secret")
				}
			}
		}

		if !foundSPA {
			t.Error("Preconfigured SPA client not found")
		}
		if !foundM2M {
			t.Error("Preconfigured M2M client not found")
		}

		t.Logf("Successfully loaded %d clients from config", len(clientList.Clients))
	})

	t.Run("UsePreconfiguredM2MClient", func(t *testing.T) {
		// Use the preconfigured M2M client credentials to authenticate
		m2, err := management.New(
			ts.URL,
			management.WithClientCredentials(
				context.Background(),
				"preconfigured_m2m",
				"preconfigured_secret_123",
			),
			management.WithInsecure(),
		)
		if err != nil {
			t.Fatalf("Failed to create management client with preconfigured credentials: %v", err)
		}

		// Test that we can use this client to make API calls
		orgs, err := m2.Organization.List(context.Background())
		if err != nil {
			t.Fatalf("Failed to list organizations with preconfigured M2M client: %v", err)
		}

		if len(orgs.Organizations) == 0 {
			t.Error("Expected at least one organization")
		}

		t.Logf("Successfully authenticated with preconfigured M2M client from config")
	})
}
