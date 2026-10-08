package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func addDeviceClient(s *Server, clientID string) {
	s.mu.Lock()
	s.clients[clientID] = &config.Client{
		ClientID:   clientID,
		Name:       "Device Test Client",
		AppType:    "native",
		GrantTypes: []string{deviceCodeGrantType},
	}
	s.mu.Unlock()
}

func addDeviceClientGrant(s *Server, clientID string, scopes ...string) {
	s.mu.Lock()
	s.clientGrants["grant_"+clientID] = &clientGrant{
		ID:       "grant_" + clientID,
		ClientID: clientID,
		Audience: s.cfg.Audience,
		Scope:    scopes,
	}
	s.mu.Unlock()
}

func issueDeviceAuthorization(t *testing.T, baseURL, clientID, audience, scope string) deviceAuthorizationResponse {
	return issueDeviceAuthorizationRequest(t, baseURL, url.Values{
		"client_id": {clientID},
		"audience":  {audience},
		"scope":     {scope},
	})
}

func issueDeviceAuthorizationForOrganization(t *testing.T, baseURL, clientID, audience, scope, organization string) deviceAuthorizationResponse {
	return issueDeviceAuthorizationRequest(t, baseURL, url.Values{
		"client_id":    {clientID},
		"audience":     {audience},
		"scope":        {scope},
		"organization": {organization},
	})
}

func issueDeviceAuthorizationRequest(t *testing.T, baseURL string, values url.Values) deviceAuthorizationResponse {
	t.Helper()
	resp, err := http.PostForm(baseURL+"/oauth/device/code", values)
	if err != nil {
		t.Fatalf("issue device code: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("issue device code: status %d: %s", resp.StatusCode, body)
	}
	var issued deviceAuthorizationResponse
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		t.Fatalf("decode device code: %v", err)
	}
	return issued
}

func deviceTokenRequest(t *testing.T, baseURL, clientID, deviceCode string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(baseURL+"/oauth/token", url.Values{
		"grant_type":  {deviceCodeGrantType},
		"client_id":   {clientID},
		"device_code": {deviceCode},
	})
	if err != nil {
		t.Fatalf("poll device token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read device token response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode device token response: %v (%s)", err, body)
	}
	return resp, decoded
}

func refreshTokenRequest(t *testing.T, baseURL, clientID, refreshToken string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(baseURL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	})
	if err != nil {
		t.Fatalf("refresh device token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read refreshed device token response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode refreshed device token response: %v (%s)", err, body)
	}
	return resp, decoded
}

func approveDevice(t *testing.T, baseURL string, issued deviceAuthorizationResponse, decision string) {
	t.Helper()
	resp, err := http.PostForm(baseURL+"/device", url.Values{
		"user_code":         {issued.UserCode},
		"confirm_user_code": {issued.UserCode},
		"identifier":        {"test@example.test"},
		"code":              {"123456"},
		"decision":          {decision},
	})
	if err != nil {
		t.Fatalf("device approval: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("device approval: status %d: %s", resp.StatusCode, body)
	}
}

func allowDevicePoll(s *Server, deviceCode string) {
	s.mu.Lock()
	if transaction := s.deviceCodes[deviceCode]; transaction != nil {
		transaction.NextPollAt = time.Time{}
	}
	s.mu.Unlock()
}

func TestDeviceAuthorizationDiscoveryAndApproval(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	var discovery map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	_ = resp.Body.Close()
	if got := discovery["device_authorization_endpoint"]; got != ts.URL+"/oauth/device/code" {
		t.Fatalf("device endpoint = %v", got)
	}

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid profile email offline_access")
	if issued.ExpiresIn != 900 || issued.Interval != 5 {
		t.Fatalf("device lifetime/interval = %d/%d, want 900/5", issued.ExpiresIn, issued.Interval)
	}
	issueResponse, err := http.PostForm(ts.URL+"/oauth/device/code", url.Values{
		"client_id": {"device_client"},
	})
	if err != nil {
		t.Fatalf("device response headers: %v", err)
	}
	_ = issueResponse.Body.Close()
	if issueResponse.Header.Get("Cache-Control") != "no-store" || issueResponse.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("device response cache headers = %q/%q", issueResponse.Header.Get("Cache-Control"), issueResponse.Header.Get("Pragma"))
	}
	if issued.DeviceCode == "" || issued.UserCode == "" || issued.VerificationURIComplete == "" {
		t.Fatal("device response omitted a required field")
	}

	verificationStart, err := http.Get(issued.VerificationURI)
	if err != nil {
		t.Fatalf("verification start page: %v", err)
	}
	startPage, _ := io.ReadAll(verificationStart.Body)
	_ = verificationStart.Body.Close()
	if verificationStart.StatusCode != http.StatusOK || !strings.Contains(string(startPage), `name="user_code"`) {
		t.Fatalf("verification start page = %d: %s", verificationStart.StatusCode, startPage)
	}

	verification, err := http.Get(issued.VerificationURIComplete)
	if err != nil {
		t.Fatalf("verification page: %v", err)
	}
	page, _ := io.ReadAll(verification.Body)
	_ = verification.Body.Close()
	if verification.StatusCode != http.StatusOK {
		t.Fatalf("verification page status = %d", verification.StatusCode)
	}
	if !strings.Contains(string(page), issued.UserCode) || strings.Contains(string(page), issued.DeviceCode) {
		t.Fatalf("verification page exposed the wrong device state: %s", page)
	}

	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	response, tokens := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approved device poll status = %d: %#v", response.StatusCode, tokens)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("device token cache headers = %q/%q", response.Header.Get("Cache-Control"), response.Header.Get("Pragma"))
	}
	if tokens["id_token"] == nil || tokens["refresh_token"] == nil {
		t.Fatalf("openid/offline_access response omitted conditional tokens: %#v", tokens)
	}
	if got := tokens["scope"]; got != "openid profile email offline_access" {
		t.Fatalf("scope = %v", got)
	}

	accessToken, ok := tokens["access_token"].(string)
	if !ok {
		t.Fatal("access token is not a string")
	}
	parsed, err := jwt.Parse(accessToken, func(token *jwt.Token) (any, error) {
		return &srv.privateKey.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("device access token signature: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "test_user_1" || claims["aud"] != srv.cfg.Audience {
		t.Fatalf("device access claims = %#v", claims)
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, srv.cfg.Issuer)
	if err != nil {
		t.Fatalf("device discovery for JWKS verification: %v", err)
	}
	verifiedAccessToken, err := provider.Verifier(&oidc.Config{ClientID: srv.cfg.Audience}).Verify(ctx, accessToken)
	if err != nil {
		t.Fatalf("device access token JWKS verification: %v", err)
	}
	if verifiedAccessToken.Subject != "test_user_1" {
		t.Fatalf("verified device access token subject = %q", verifiedAccessToken.Subject)
	}
	verifiedIDToken, err := provider.Verifier(&oidc.Config{ClientID: "device_client"}).Verify(ctx, tokens["id_token"].(string))
	if err != nil {
		t.Fatalf("device ID token JWKS verification: %v", err)
	}
	if verifiedIDToken.Subject != "test_user_1" {
		t.Fatalf("verified device ID token subject = %q", verifiedIDToken.Subject)
	}

	replay, replayBody := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if replay.StatusCode != http.StatusBadRequest || replayBody["error"] != "invalid_grant" {
		t.Fatalf("device replay = %d %#v", replay.StatusCode, replayBody)
	}
}

func TestDeviceAuthorizationScopesAndAudience(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	addDeviceClientGrant(srv, "device_client", "read:things")

	withoutAudience := issueDeviceAuthorization(t, ts.URL, "device_client", "", "openid")
	approveDevice(t, ts.URL, withoutAudience, "approve")
	allowDevicePoll(srv, withoutAudience.DeviceCode)
	withoutAudienceResponse, withoutAudienceBody := deviceTokenRequest(t, ts.URL, "device_client", withoutAudience.DeviceCode)
	if withoutAudienceResponse.StatusCode != http.StatusOK || withoutAudienceBody["access_token"] == nil {
		t.Fatalf("device authorization without audience = %d %#v", withoutAudienceResponse.StatusCode, withoutAudienceBody)
	}

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid read:things read:things")
	if issued.UserCode == "" {
		t.Fatal("client-grant scope request did not issue a code")
	}

	cases := []struct {
		name   string
		values url.Values
		status int
		err    string
	}{
		{
			name:   "unknown scope",
			values: url.Values{"client_id": {"device_client"}, "audience": {srv.cfg.Audience}, "scope": {"openid write:things"}},
			status: http.StatusBadRequest,
			err:    "invalid_scope",
		},
		{
			name:   "wrong audience",
			values: url.Values{"client_id": {"device_client"}, "audience": {"https://other.example"}},
			status: http.StatusBadRequest,
			err:    "invalid_request",
		},
		{
			name:   "disagreeing resource",
			values: url.Values{"client_id": {"device_client"}, "audience": {srv.cfg.Audience}, "resource": {"https://other.example"}},
			status: http.StatusBadRequest,
			err:    "invalid_request",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.PostForm(ts.URL+"/oauth/device/code", tc.values)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			if resp.StatusCode != tc.status || body["error"] != tc.err {
				t.Fatalf("response = %d %#v", resp.StatusCode, body)
			}
		})
	}
}

func TestDeviceAuthorizationClientBinding(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	addDeviceClient(srv, "other_device_client")
	srv.mu.Lock()
	srv.clients["native_without_device_grant"] = &config.Client{
		ClientID: "native_without_device_grant",
		AppType:  "native",
	}
	srv.mu.Unlock()

	unknown, err := http.PostForm(ts.URL+"/oauth/device/code", url.Values{
		"client_id": {"unknown_client"},
	})
	if err != nil {
		t.Fatalf("unknown client request: %v", err)
	}
	var unknownBody map[string]any
	_ = json.NewDecoder(unknown.Body).Decode(&unknownBody)
	_ = unknown.Body.Close()
	if unknown.StatusCode != http.StatusUnauthorized || unknownBody["error"] != "invalid_client" {
		t.Fatalf("unknown client response = %d %#v", unknown.StatusCode, unknownBody)
	}

	withoutGrant, err := http.PostForm(ts.URL+"/oauth/device/code", url.Values{
		"client_id": {"native_without_device_grant"},
	})
	if err != nil {
		t.Fatalf("native client without grant request: %v", err)
	}
	var withoutGrantBody map[string]any
	_ = json.NewDecoder(withoutGrant.Body).Decode(&withoutGrantBody)
	_ = withoutGrant.Body.Close()
	if withoutGrant.StatusCode != http.StatusUnauthorized || withoutGrantBody["error"] != "invalid_client" {
		t.Fatalf("native client without grant response = %d %#v", withoutGrant.StatusCode, withoutGrantBody)
	}

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid")
	mismatch, mismatchBody := deviceTokenRequest(t, ts.URL, "other_device_client", issued.DeviceCode)
	if mismatch.StatusCode != http.StatusBadRequest || mismatchBody["error"] != "invalid_grant" {
		t.Fatalf("client mismatch response = %d %#v", mismatch.StatusCode, mismatchBody)
	}

	nonNative, nonNativeBody := deviceTokenRequest(t, ts.URL, "mgmt_client_dev", issued.DeviceCode)
	if nonNative.StatusCode != http.StatusUnauthorized || nonNativeBody["error"] != "invalid_client" {
		t.Fatalf("non-native polling response = %d %#v", nonNative.StatusCode, nonNativeBody)
	}

	unknownPoll, unknownPollBody := deviceTokenRequest(t, ts.URL, "unknown_client", issued.DeviceCode)
	if unknownPoll.StatusCode != http.StatusUnauthorized || unknownPollBody["error"] != "invalid_client" {
		t.Fatalf("unknown-client polling response = %d %#v", unknownPoll.StatusCode, unknownPollBody)
	}
}

func TestDeviceRefreshTokenRoundTrip(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	addDeviceClient(srv, "other_device_client")

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid offline_access")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	initialResponse, initialTokens := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if initialResponse.StatusCode != http.StatusOK {
		t.Fatalf("initial device exchange = %d %#v", initialResponse.StatusCode, initialTokens)
	}
	refreshToken, ok := initialTokens["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("initial device exchange omitted refresh token: %#v", initialTokens)
	}

	refreshResponse, refreshedTokens := refreshTokenRequest(t, ts.URL, "device_client", refreshToken)
	if refreshResponse.StatusCode != http.StatusOK {
		t.Fatalf("device refresh exchange = %d %#v", refreshResponse.StatusCode, refreshedTokens)
	}
	for _, tokenName := range []string{"access_token", "id_token"} {
		if refreshedTokens[tokenName] == nil {
			t.Errorf("device refresh response omitted %s: %#v", tokenName, refreshedTokens)
		}
	}
	// A non-rotating client, as an Auth0 application is by default, gets no
	// refresh token back and keeps using the one it has.
	if _, ok := refreshedTokens["refresh_token"]; ok {
		t.Errorf("non-rotating refresh response included a refresh token: %#v", refreshedTokens)
	}
	if refreshedTokens["scope"] != "openid offline_access" {
		t.Fatalf("device refresh scope = %v", refreshedTokens["scope"])
	}
	parsed, err := jwt.Parse(refreshedTokens["access_token"].(string), func(token *jwt.Token) (any, error) {
		return &srv.privateKey.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("refreshed device access token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["aud"] != srv.cfg.Audience || claims["scope"] != "openid offline_access" {
		t.Fatalf("refreshed device access claims = %#v", claims)
	}

	wrongClient, wrongClientBody := refreshTokenRequest(t, ts.URL, "other_device_client", refreshToken)
	if wrongClient.StatusCode != http.StatusBadRequest || wrongClientBody["error"] != "invalid_grant" {
		t.Fatalf("refresh with a different client = %d %#v", wrongClient.StatusCode, wrongClientBody)
	}

	again, againTokens := refreshTokenRequest(t, ts.URL, "device_client", refreshToken)
	if again.StatusCode != http.StatusOK {
		t.Fatalf("second non-rotating refresh = %d %#v", again.StatusCode, againTokens)
	}
}

func TestDeviceRefreshTokenRotation(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	srv.mu.Lock()
	srv.clients["device_client"].RefreshToken = &config.RefreshTokenConfig{RotationType: config.RefreshTokenRotating}
	srv.mu.Unlock()

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid offline_access")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	_, initialTokens := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	first, _ := initialTokens["refresh_token"].(string)
	if first == "" {
		t.Fatalf("initial device exchange omitted refresh token: %#v", initialTokens)
	}

	refreshed, refreshedTokens := refreshTokenRequest(t, ts.URL, "device_client", first)
	second, _ := refreshedTokens["refresh_token"].(string)
	if refreshed.StatusCode != http.StatusOK || second == "" || second == first {
		t.Fatalf("rotating refresh = %d, refresh token %q after %q", refreshed.StatusCode, second, first)
	}

	reused, reusedBody := refreshTokenRequest(t, ts.URL, "device_client", first)
	if reused.StatusCode != http.StatusForbidden || reusedBody["error"] != "invalid_grant" {
		t.Fatalf("reusing a rotated refresh token = %d %#v", reused.StatusCode, reusedBody)
	}

	next, nextTokens := refreshTokenRequest(t, ts.URL, "device_client", second)
	if next.StatusCode != http.StatusOK || nextTokens["refresh_token"] == nil {
		t.Fatalf("refresh with the rotated token = %d %#v", next.StatusCode, nextTokens)
	}
}

func TestDeviceAuthorizationOrganizationScope(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")

	issued := issueDeviceAuthorizationForOrganization(t, ts.URL, "device_client", srv.cfg.Audience, "openid", "org_test")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	response, tokens := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("organization device exchange = %d %#v", response.StatusCode, tokens)
	}

	accessToken, ok := tokens["access_token"].(string)
	if !ok {
		t.Fatal("organization device response omitted access token")
	}
	parsed, err := jwt.Parse(accessToken, func(token *jwt.Token) (any, error) {
		return &srv.privateKey.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("organization device access token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["org_id"] != "org_test" || claims[srv.cfg.Issuer+"role"] != "admin" {
		t.Fatalf("organization device access claims = %#v", claims)
	}
}

func TestDeviceAuthorizationRejectsNonMemberOrganization(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	srv.mu.Lock()
	srv.organizations["org_other"] = &config.Organization{ID: "org_other", Name: "other-org"}
	srv.mu.Unlock()

	issued := issueDeviceAuthorizationForOrganization(t, ts.URL, "device_client", srv.cfg.Audience, "openid", "org_other")
	response, err := http.PostForm(ts.URL+"/device", url.Values{
		"user_code":         {issued.UserCode},
		"confirm_user_code": {issued.UserCode},
		"identifier":        {"test@example.test"},
		"code":              {"123456"},
		"decision":          {"approve"},
	})
	if err != nil {
		t.Fatalf("nonmember device approval: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "not a member") {
		t.Fatalf("nonmember device approval = %d: %s", response.StatusCode, body)
	}
}

func TestDeviceAuthorizationAudienceMutationInvalidatesCode(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid")
	srv.mu.Lock()
	srv.deviceCodes[issued.DeviceCode].Audience = "https://mutated.example"
	srv.mu.Unlock()

	response, body := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if response.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("mutated audience response = %d %#v", response.StatusCode, body)
	}
}

func TestDeviceVerificationRateLimit(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid")

	for attempt := 0; attempt < 5; attempt++ {
		response, err := http.PostForm(ts.URL+"/device", url.Values{
			"user_code":         {issued.UserCode},
			"confirm_user_code": {issued.UserCode},
			"identifier":        {"test@example.test"},
			"code":              {"000000"},
			"decision":          {"approve"},
		})
		if err != nil {
			t.Fatalf("verification attempt %d: %v", attempt+1, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("verification attempt %d status = %d, want 400", attempt+1, response.StatusCode)
		}
	}

	blocked, err := http.PostForm(ts.URL+"/device", url.Values{
		"user_code":         {issued.UserCode},
		"confirm_user_code": {issued.UserCode},
		"identifier":        {"test@example.test"},
		"code":              {"000000"},
		"decision":          {"approve"},
	})
	if err != nil {
		t.Fatalf("blocked verification attempt: %v", err)
	}
	_ = blocked.Body.Close()
	if blocked.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("blocked verification status = %d, want 429", blocked.StatusCode)
	}
}

func TestDevicePostLoginActionUsesDeviceProtocol(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	m := mgmt{t: t, url: ts.URL}
	m.deployBound("device-protocol", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/protocol", event.transaction.protocol);
			  api.accessToken.setCustomClaim("https://mock/scopes", event.transaction.requested_scopes.join(" "));
		};`)

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	response, tokens := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("device token status = %d: %#v", response.StatusCode, tokens)
	}
	accessToken, ok := tokens["access_token"].(string)
	if !ok {
		t.Fatal("device action response omitted access token")
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse device access token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["https://mock/protocol"] != "oauth2-device-code" || claims["https://mock/scopes"] != "openid" {
		t.Fatalf("device action protocol = %#v", parsed.Claims)
	}
}

func TestDeviceLoginIsASessionKeptAcrossRefresh(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	m := mgmt{t: t, url: ts.URL}
	m.deployBound("device-session", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/sid", event.session && event.session.id);
		};`)

	login := func() map[string]any {
		t.Helper()
		issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid offline_access")
		approveDevice(t, ts.URL, issued, "approve")
		allowDevicePoll(srv, issued.DeviceCode)
		response, tokens := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("device token status = %d: %#v", response.StatusCode, tokens)
		}
		return tokens
	}

	tokens := login()
	sid, _ := claims(t, tokens["access_token"])["https://mock/sid"].(string)
	if sid == "" {
		t.Fatalf("no session id in the action: %#v", claims(t, tokens["access_token"]))
	}
	if got := claims(t, tokens["id_token"])["sid"]; got != sid {
		t.Fatalf("id token sid = %v, want %s", got, sid)
	}

	refreshResponse, refreshed := refreshTokenRequest(t, ts.URL, "device_client", tokens["refresh_token"].(string))
	if refreshResponse.StatusCode != http.StatusOK {
		t.Fatalf("device refresh = %d %#v", refreshResponse.StatusCode, refreshed)
	}
	if got := claims(t, refreshed["access_token"])["https://mock/sid"]; got != sid {
		t.Fatalf("refreshed action sid = %v, want %s", got, sid)
	}
	if got := claims(t, refreshed["id_token"])["sid"]; got != sid {
		t.Fatalf("refreshed id token sid = %v, want %s", got, sid)
	}

	if other := claims(t, login()["access_token"])["https://mock/sid"]; other == sid {
		t.Fatal("a new device login reused the session id")
	}
}

func TestDevicePollingStatusesAndConditionalTokens(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "profile")
	pending, pendingBody := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if pending.StatusCode != http.StatusForbidden || pendingBody["error"] != "authorization_pending" {
		t.Fatalf("first poll = %d %#v", pending.StatusCode, pendingBody)
	}
	slow, slowBody := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if slow.StatusCode != http.StatusTooManyRequests || slowBody["error"] != "slow_down" {
		t.Fatalf("fast poll = %d %#v", slow.StatusCode, slowBody)
	}
	srv.mu.RLock()
	interval := srv.deviceCodes[issued.DeviceCode].Interval
	srv.mu.RUnlock()
	if interval != 10*time.Second {
		t.Fatalf("slow_down interval = %s, want 10s", interval)
	}

	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	approved, approvedBody := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if approved.StatusCode != http.StatusOK || approvedBody["id_token"] != nil || approvedBody["refresh_token"] != nil {
		t.Fatalf("profile-only device response = %d %#v", approved.StatusCode, approvedBody)
	}

	denied := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid")
	approveDevice(t, ts.URL, denied, "deny")
	deniedResponse, deniedBody := deviceTokenRequest(t, ts.URL, "device_client", denied.DeviceCode)
	if deniedResponse.StatusCode != http.StatusForbidden || deniedBody["error"] != "access_denied" {
		t.Fatalf("denied device = %d %#v", deniedResponse.StatusCode, deniedBody)
	}

	expired := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid")
	srv.mu.Lock()
	srv.deviceCodes[expired.DeviceCode].ExpiresAt = time.Now().Add(-time.Second)
	srv.mu.Unlock()
	expiredResponse, expiredBody := deviceTokenRequest(t, ts.URL, "device_client", expired.DeviceCode)
	if expiredResponse.StatusCode != http.StatusForbidden || expiredBody["error"] != "expired_token" {
		t.Fatalf("expired device = %d %#v", expiredResponse.StatusCode, expiredBody)
	}
	secondExpired, secondExpiredBody := deviceTokenRequest(t, ts.URL, "device_client", expired.DeviceCode)
	if secondExpired.StatusCode != http.StatusBadRequest || secondExpiredBody["error"] != "invalid_grant" {
		t.Fatalf("expired replay = %d %#v", secondExpired.StatusCode, secondExpiredBody)
	}
}

func TestConfiguredDeviceCodeLifetime(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	srv.cfg.DeviceCodeLifetime = 2 * time.Second

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid")
	if issued.ExpiresIn != 2 {
		t.Fatalf("expires_in = %d, want 2", issued.ExpiresIn)
	}
	srv.mu.RLock()
	window := srv.deviceCodes[issued.DeviceCode].ExpiresAt.Sub(srv.deviceCodes[issued.DeviceCode].CreatedAt)
	srv.mu.RUnlock()
	if window != 2*time.Second {
		t.Fatalf("transaction window = %s, want 2s", window)
	}
}

func TestConcurrentDeviceExchangeYieldsExactlyOneToken(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "openid")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)

	const attempts = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
				"grant_type":  {deviceCodeGrantType},
				"client_id":   {"device_client"},
				"device_code": {issued.DeviceCode},
			})
			if err != nil {
				t.Errorf("concurrent device poll: %v", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != 1 {
		t.Fatalf("concurrent device exchanges granted %d tokens, want 1", granted)
	}
}

func TestDeviceTokenHandlesDeletedApprover(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	addDeviceClient(srv, "device_client")

	issued := issueDeviceAuthorization(t, ts.URL, "device_client", srv.cfg.Audience, "profile")
	approveDevice(t, ts.URL, issued, "approve")
	srv.mu.Lock()
	delete(srv.users, "test_user_1")
	srv.mu.Unlock()
	allowDevicePoll(srv, issued.DeviceCode)

	response, body := deviceTokenRequest(t, ts.URL, "device_client", issued.DeviceCode)
	if response.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("deleted approver response = %d %#v", response.StatusCode, body)
	}
}
