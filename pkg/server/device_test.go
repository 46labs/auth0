package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"

	"github.com/46labs/auth0/pkg/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// addNativeClient creates a native application with grantTypes and returns
// its generated client id.
func addNativeClient(t *testing.T, m *management.Management, name string, grantTypes ...string) string {
	t.Helper()
	client := &management.Client{Name: auth0.String(name), AppType: auth0.String("native"), GrantTypes: &grantTypes}
	if err := m.Client.Create(context.Background(), client); err != nil {
		t.Fatalf("create client %s: %v", name, err)
	}
	return client.GetClientID()
}

// addDeviceClient creates a native application allowed the device grant.
func addDeviceClient(t *testing.T, m *management.Management, name string) string {
	t.Helper()
	return addNativeClient(t, m, name, deviceCodeGrantType)
}

func addDeviceClientGrant(t *testing.T, m *management.Management, clientID, audience string, scopes ...string) {
	t.Helper()
	grant := &management.ClientGrant{ClientID: auth0.String(clientID), Audience: auth0.String(audience), Scope: &scopes}
	if err := m.ClientGrant.Create(context.Background(), grant); err != nil {
		t.Fatalf("create client grant: %v", err)
	}
}

// setRefreshTokenRotation switches a client to rotating refresh tokens with
// leeway seconds of reuse interval.
func setRefreshTokenRotation(t *testing.T, m *management.Management, clientID string, leeway int) {
	t.Helper()
	update := &management.Client{RefreshToken: &management.ClientRefreshToken{
		RotationType: auth0.String("rotating"), ExpirationType: auth0.String("expiring"), Leeway: auth0.Int(leeway),
	}}
	if err := m.Client.Update(context.Background(), clientID, update); err != nil {
		t.Fatalf("enable refresh token rotation: %v", err)
	}
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

// Raw HTTP: the SDK has no /oauth/device/code call, and /oauth/token and
// /device are the OIDC and browser flows AGENTS.md leaves to it.
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
	return postToken(t, baseURL, url.Values{"grant_type": {deviceCodeGrantType}, "client_id": {clientID}, "device_code": {deviceCode}})
}

func refreshTokenRequest(t *testing.T, baseURL, clientID, refreshToken string) (*http.Response, map[string]any) {
	t.Helper()
	return postToken(t, baseURL, url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refreshToken}})
}

// postToken posts values to /oauth/token and decodes the JSON answer.
func postToken(t *testing.T, baseURL string, values url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(baseURL+"/oauth/token", values)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read token response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode token response: %v (%s)", err, body)
	}
	return resp, decoded
}

// deviceTokens runs the device flow for clientID through to its tokens.
func deviceTokens(t *testing.T, srv *Server, baseURL, clientID, scope string) map[string]any {
	t.Helper()
	issued := issueDeviceAuthorization(t, baseURL, clientID, srv.cfg.Audience, scope)
	approveDevice(t, baseURL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	response, tokens := deviceTokenRequest(t, baseURL, clientID, issued.DeviceCode)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("device exchange = %d %#v", response.StatusCode, tokens)
	}
	return tokens
}

// bindPostLoginAction creates, deploys and binds a post-login Action through
// the Management API.
func bindPostLoginAction(t *testing.T, m *management.Management, name, code string) {
	t.Helper()
	ctx := context.Background()
	action := &management.Action{Name: auth0.String(name), Code: auth0.String(code),
		SupportedTriggers: []management.ActionTrigger{{ID: auth0.String("post-login"), Version: auth0.String("v3")}}}
	if err := m.Action.Create(ctx, action); err != nil {
		t.Fatalf("create action: %v", err)
	}
	if _, err := m.Action.Deploy(ctx, action.GetID()); err != nil {
		t.Fatalf("deploy action: %v", err)
	}
	binding := []*management.ActionBinding{{Ref: &management.ActionBindingReference{Type: auth0.String("action_id"), Value: action.ID}, DisplayName: auth0.String(name)}}
	if err := m.Action.UpdateBindings(ctx, "post-login", binding); err != nil {
		t.Fatalf("bind action: %v", err)
	}
}

// postDevice submits the device page as identifier and returns the status and
// body. It reports with t.Errorf, so a goroutine may call it.
func postDevice(t *testing.T, baseURL, userCode, identifier, code, decision string) (int, string) {
	t.Helper()
	resp, err := http.PostForm(baseURL+"/device", url.Values{
		"user_code": {userCode}, "confirm_user_code": {userCode},
		"identifier": {identifier}, "code": {code}, "decision": {decision},
	})
	if err != nil {
		t.Errorf("device post: %v", err)
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func approveDevice(t *testing.T, baseURL string, issued deviceAuthorizationResponse, decision string) {
	t.Helper()
	if status, body := postDevice(t, baseURL, issued.UserCode, "test@example.test", "123456", decision); status != http.StatusOK {
		t.Fatalf("device %s: status %d: %s", decision, status, body)
	}
}

// addOtherOrganization creates an organization the test user may sign in to
// but is not a member of.
func addOtherOrganization(t *testing.T, m *management.Management) string {
	t.Helper()
	org := &management.Organization{Name: auth0.String("other-org")}
	if err := m.Organization.Create(context.Background(), org); err != nil {
		t.Fatalf("create organization: %v", err)
	}
	if err := m.Organization.AddConnection(context.Background(), org.GetID(),
		&management.OrganizationConnection{ConnectionID: auth0.String("con_email")}); err != nil {
		t.Fatalf("enable connection: %v", err)
	}
	return org.GetID()
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
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")

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

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid profile email offline_access")
	if issued.ExpiresIn != 900 || issued.Interval != 5 {
		t.Fatalf("device lifetime/interval = %d/%d, want 900/5", issued.ExpiresIn, issued.Interval)
	}
	issueResponse, err := http.PostForm(ts.URL+"/oauth/device/code", url.Values{
		"client_id": {deviceClient},
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
	response, tokens := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
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
	verifiedIDToken, err := provider.Verifier(&oidc.Config{ClientID: deviceClient}).Verify(ctx, tokens["id_token"].(string))
	if err != nil {
		t.Fatalf("device ID token JWKS verification: %v", err)
	}
	if verifiedIDToken.Subject != "test_user_1" {
		t.Fatalf("verified device ID token subject = %q", verifiedIDToken.Subject)
	}

	replay, replayBody := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	if replay.StatusCode != http.StatusBadRequest || replayBody["error"] != "invalid_grant" {
		t.Fatalf("device replay = %d %#v", replay.StatusCode, replayBody)
	}
}

func TestDeviceAuthorizationScopesAndAudience(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	addDeviceClientGrant(t, dm, deviceClient, srv.cfg.Audience, "read:things")

	withoutAudience := issueDeviceAuthorization(t, ts.URL, deviceClient, "", "openid")
	approveDevice(t, ts.URL, withoutAudience, "approve")
	allowDevicePoll(srv, withoutAudience.DeviceCode)
	withoutAudienceResponse, withoutAudienceBody := deviceTokenRequest(t, ts.URL, deviceClient, withoutAudience.DeviceCode)
	if withoutAudienceResponse.StatusCode != http.StatusOK || withoutAudienceBody["access_token"] == nil {
		t.Fatalf("device authorization without audience = %d %#v", withoutAudienceResponse.StatusCode, withoutAudienceBody)
	}

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid read:things read:things")
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
			values: url.Values{"client_id": {deviceClient}, "audience": {srv.cfg.Audience}, "scope": {"openid write:things"}},
			status: http.StatusBadRequest,
			err:    "invalid_scope",
		},
		{
			name:   "wrong audience",
			values: url.Values{"client_id": {deviceClient}, "audience": {"https://other.example"}},
			status: http.StatusBadRequest,
			err:    "invalid_request",
		},
		{
			name:   "disagreeing resource",
			values: url.Values{"client_id": {deviceClient}, "audience": {srv.cfg.Audience}, "resource": {"https://other.example"}},
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
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	otherDeviceClient := addDeviceClient(t, dm, "other_device_client")
	withoutDeviceGrant := addNativeClient(t, dm, "native_without_device_grant")

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
		"client_id": {withoutDeviceGrant},
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

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	mismatch, mismatchBody := deviceTokenRequest(t, ts.URL, otherDeviceClient, issued.DeviceCode)
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
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	otherDeviceClient := addDeviceClient(t, dm, "other_device_client")

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid offline_access")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	initialResponse, initialTokens := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	if initialResponse.StatusCode != http.StatusOK {
		t.Fatalf("initial device exchange = %d %#v", initialResponse.StatusCode, initialTokens)
	}
	refreshToken, ok := initialTokens["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("initial device exchange omitted refresh token: %#v", initialTokens)
	}

	refreshResponse, refreshedTokens := refreshTokenRequest(t, ts.URL, deviceClient, refreshToken)
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

	wrongClient, wrongClientBody := refreshTokenRequest(t, ts.URL, otherDeviceClient, refreshToken)
	if wrongClient.StatusCode != http.StatusBadRequest || wrongClientBody["error"] != "invalid_grant" {
		t.Fatalf("refresh with a different client = %d %#v", wrongClient.StatusCode, wrongClientBody)
	}

	again, againTokens := refreshTokenRequest(t, ts.URL, deviceClient, refreshToken)
	if again.StatusCode != http.StatusOK {
		t.Fatalf("second non-rotating refresh = %d %#v", again.StatusCode, againTokens)
	}
}

func TestDeviceRefreshTokenRotation(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	setRefreshTokenRotation(t, dm, deviceClient, 0)

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid offline_access")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	_, initialTokens := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	first, _ := initialTokens["refresh_token"].(string)
	if first == "" {
		t.Fatalf("initial device exchange omitted refresh token: %#v", initialTokens)
	}

	refreshed, refreshedTokens := refreshTokenRequest(t, ts.URL, deviceClient, first)
	second, _ := refreshedTokens["refresh_token"].(string)
	if refreshed.StatusCode != http.StatusOK || second == "" || second == first {
		t.Fatalf("rotating refresh = %d, refresh token %q after %q", refreshed.StatusCode, second, first)
	}

	next, nextTokens := refreshTokenRequest(t, ts.URL, deviceClient, second)
	third, _ := nextTokens["refresh_token"].(string)
	if next.StatusCode != http.StatusOK || third == "" {
		t.Fatalf("refresh with the rotated token = %d %#v", next.StatusCode, nextTokens)
	}

	// Without a leeway, reuse is a breach: the token and its whole family are revoked.
	reused, reusedBody := refreshTokenRequest(t, ts.URL, deviceClient, first)
	if reused.StatusCode != http.StatusForbidden || reusedBody["error"] != "invalid_grant" {
		t.Fatalf("reusing a rotated refresh token = %d %#v", reused.StatusCode, reusedBody)
	}
	revoked, revokedBody := refreshTokenRequest(t, ts.URL, deviceClient, third)
	if revoked.StatusCode != http.StatusForbidden || revokedBody["error"] != "invalid_grant" {
		t.Fatalf("newest refresh token after a reuse = %d %#v", revoked.StatusCode, revokedBody)
	}
}

func TestDeviceRefreshTokenLeeway(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	setRefreshTokenRotation(t, dm, deviceClient, 120)

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid offline_access")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	_, initialTokens := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	first, _ := initialTokens["refresh_token"].(string)
	_, refreshedTokens := refreshTokenRequest(t, ts.URL, deviceClient, first)
	second, _ := refreshedTokens["refresh_token"].(string)

	// Within the leeway the token just retired is exchanged, as a concurrent refresh would present it.
	reused, reusedTokens := refreshTokenRequest(t, ts.URL, deviceClient, first)
	if reused.StatusCode != http.StatusOK || reusedTokens["refresh_token"] == nil {
		t.Fatalf("reuse within the leeway = %d %#v", reused.StatusCode, reusedTokens)
	}
	next, nextTokens := refreshTokenRequest(t, ts.URL, deviceClient, second)
	third, _ := nextTokens["refresh_token"].(string)
	if next.StatusCode != http.StatusOK || third == "" {
		t.Fatalf("refresh after a reuse within the leeway = %d %#v", next.StatusCode, nextTokens)
	}

	// The leeway covers only the latest retired token: first is older than second now.
	stale, staleBody := refreshTokenRequest(t, ts.URL, deviceClient, first)
	if stale.StatusCode != http.StatusForbidden || staleBody["error"] != "invalid_grant" {
		t.Fatalf("reuse of an older retired token = %d %#v", stale.StatusCode, staleBody)
	}
	revoked, _ := refreshTokenRequest(t, ts.URL, deviceClient, third)
	if revoked.StatusCode != http.StatusForbidden {
		t.Fatalf("newest refresh token after a breach = %d", revoked.StatusCode)
	}
}

func TestRefreshTokenLeewayExpires(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	client := addDeviceClient(t, dm, "rotating")
	setRefreshTokenRotation(t, dm, client, 120)
	srv.mu.Lock()
	srv.refreshTokens["rt_first"] = &refreshTokenState{ClientID: client, Family: "rt_first"}
	srv.mu.Unlock()

	start := time.Now()
	state, release, _, _ := srv.claimRefreshToken("rt_first", client, start)
	release()
	if state == nil {
		t.Fatal("first refresh refused")
	}
	if rotated, _, _ := srv.rotateRefreshToken("rt_first", state); rotated == "" {
		t.Fatal("rotating client did not rotate")
	}
	if state, _, _, status := srv.claimRefreshToken("rt_first", client, start.Add(121*time.Second)); state != nil || status != http.StatusForbidden {
		t.Fatalf("reuse after the leeway = %v %d", state, status)
	}
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if len(srv.refreshTokens) != 0 {
		t.Fatalf("family survived a reuse after the leeway: %d live tokens", len(srv.refreshTokens))
	}
}

func TestDeviceAuthorizationOrganizationScope(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")

	issued := issueDeviceAuthorizationForOrganization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid", "org_test")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	response, tokens := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
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
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	other := addOtherOrganization(t, dm)

	issued := issueDeviceAuthorizationForOrganization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid", other)
	if status, body := postDevice(t, ts.URL, issued.UserCode, "test@example.test", "123456", "approve"); status != http.StatusBadRequest || !strings.Contains(body, "not a member") {
		t.Fatalf("nonmember device approval = %d: %s", status, body)
	}
}

func TestDeviceAuthorizationAudienceMutationInvalidatesCode(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	srv.mu.Lock()
	srv.deviceCodes[issued.DeviceCode].Audience = "https://mutated.example"
	srv.mu.Unlock()

	response, body := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	if response.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("mutated audience response = %d %#v", response.StatusCode, body)
	}
}

func TestDeviceVerificationRateLimit(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")

	for attempt := 0; attempt < 5; attempt++ {
		if status, _ := postDevice(t, ts.URL, issued.UserCode, "test@example.test", "000000", "approve"); status != http.StatusBadRequest {
			t.Fatalf("verification attempt %d status = %d, want 400", attempt+1, status)
		}
	}

	if status, _ := postDevice(t, ts.URL, issued.UserCode, "test@example.test", "000000", "approve"); status != http.StatusTooManyRequests {
		t.Fatalf("blocked verification status = %d, want 429", status)
	}
}

func TestDevicePostLoginActionUsesDeviceProtocol(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	m := mgmt{t: t, url: ts.URL}
	m.deployBound("device-protocol", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/protocol", event.transaction.protocol);
			  api.accessToken.setCustomClaim("https://mock/scopes", event.transaction.requested_scopes.join(" "));
		};`)

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	approveDevice(t, ts.URL, issued, "approve")
	allowDevicePoll(srv, issued.DeviceCode)
	response, tokens := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
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
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	m := mgmt{t: t, url: ts.URL}
	m.deployBound("device-session", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/sid", event.session && event.session.id);
		};`)

	login := func() map[string]any {
		t.Helper()
		issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid offline_access")
		approveDevice(t, ts.URL, issued, "approve")
		allowDevicePoll(srv, issued.DeviceCode)
		response, tokens := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
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

	refreshResponse, refreshed := refreshTokenRequest(t, ts.URL, deviceClient, tokens["refresh_token"].(string))
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
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "profile")
	pending, pendingBody := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	if pending.StatusCode != http.StatusForbidden || pendingBody["error"] != "authorization_pending" {
		t.Fatalf("first poll = %d %#v", pending.StatusCode, pendingBody)
	}
	slow, slowBody := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
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
	approved, approvedBody := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	if approved.StatusCode != http.StatusOK || approvedBody["id_token"] != nil || approvedBody["refresh_token"] != nil {
		t.Fatalf("profile-only device response = %d %#v", approved.StatusCode, approvedBody)
	}

	denied := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	approveDevice(t, ts.URL, denied, "deny")
	deniedResponse, deniedBody := deviceTokenRequest(t, ts.URL, deviceClient, denied.DeviceCode)
	if deniedResponse.StatusCode != http.StatusForbidden || deniedBody["error"] != "access_denied" {
		t.Fatalf("denied device = %d %#v", deniedResponse.StatusCode, deniedBody)
	}

	expired := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	srv.mu.Lock()
	srv.deviceCodes[expired.DeviceCode].ExpiresAt = time.Now().Add(-time.Second)
	srv.mu.Unlock()
	expiredResponse, expiredBody := deviceTokenRequest(t, ts.URL, deviceClient, expired.DeviceCode)
	if expiredResponse.StatusCode != http.StatusForbidden || expiredBody["error"] != "expired_token" {
		t.Fatalf("expired device = %d %#v", expiredResponse.StatusCode, expiredBody)
	}
	secondExpired, secondExpiredBody := deviceTokenRequest(t, ts.URL, deviceClient, expired.DeviceCode)
	if secondExpired.StatusCode != http.StatusBadRequest || secondExpiredBody["error"] != "invalid_grant" {
		t.Fatalf("expired replay = %d %#v", secondExpired.StatusCode, secondExpiredBody)
	}
}

func TestConfiguredDeviceCodeLifetime(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	srv.cfg.DeviceCodeLifetime = 2 * time.Second

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
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
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
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
				"client_id":   {deviceClient},
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
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")

	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "profile")
	approveDevice(t, ts.URL, issued, "approve")
	if err := dm.User.Delete(context.Background(), "test_user_1"); err != nil {
		t.Fatalf("delete approver: %v", err)
	}
	allowDevicePoll(srv, issued.DeviceCode)

	response, body := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	if response.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("deleted approver response = %d %#v", response.StatusCode, body)
	}
}

// refresh_token round-trips through the Management API with Auth0's defaults,
// and a value Auth0 refuses is refused without changing the client.
func TestClientRefreshTokenThroughSDK(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := newMgmt(t, ts.URL)
	ctx := context.Background()

	policies := []management.ClientRefreshTokenPolicy{{Audience: auth0.String("https://api.test"), Scope: &[]string{"read:things"}}}
	client := &management.Client{Name: auth0.String("refreshing"), AppType: auth0.String("native"),
		RefreshToken: &management.ClientRefreshToken{RotationType: auth0.String("non-rotating"), ExpirationType: auth0.String("non-expiring"), Policies: &policies}}
	if err := m.Client.Create(ctx, client); err != nil {
		t.Fatalf("create: %v", err)
	}
	id := client.GetClientID()
	if err := m.Client.Update(ctx, id, &management.Client{RefreshToken: &management.ClientRefreshToken{
		RotationType: auth0.String("rotating"), Leeway: auth0.Int(30), TokenLifetime: auth0.Int(3600),
	}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	read, err := m.Client.Read(ctx, id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	rt := read.GetRefreshToken()
	if rt.GetRotationType() != "rotating" || rt.GetExpirationType() != "non-expiring" || rt.GetLeeway() != 30 || rt.GetTokenLifetime() != 3600 {
		t.Fatalf("refresh_token = %+v", rt)
	}
	if got := rt.GetPolicies(); len(got) != 1 || got[0].GetAudience() != "https://api.test" || len(got[0].GetScope()) != 1 {
		t.Fatalf("policies = %+v", got)
	}

	err = m.Client.Update(ctx, id, &management.Client{RefreshToken: &management.ClientRefreshToken{RotationType: auth0.String("sometimes")}})
	if statusOf(err) != http.StatusBadRequest {
		t.Fatalf("invalid rotation_type = %v", err)
	}
	if read, err = m.Client.Read(ctx, id); err != nil || read.GetRefreshToken().GetRotationType() != "rotating" {
		t.Fatalf("a refused update changed the client: %+v %v", read.GetRefreshToken(), err)
	}
	// Auth0 fills the rest on create (go-auth0's TestClient_Create and
	// TestClient_CreateWithClientRefreshToken recordings).
	for _, tc := range []struct {
		sent     *management.ClientRefreshToken
		infinite bool
	}{
		{sent: nil, infinite: true},
		{sent: &management.ClientRefreshToken{ExpirationType: auth0.String("expiring")}, infinite: false},
	} {
		created := &management.Client{Name: auth0.String("defaults"), RefreshToken: tc.sent}
		if err := m.Client.Create(ctx, created); err != nil {
			t.Fatalf("create: %v", err)
		}
		rt := created.GetRefreshToken()
		if rt.GetRotationType() != "non-rotating" || rt.Leeway == nil || rt.GetTokenLifetime() != 2592000 || rt.GetIdleTokenLifetime() != 1296000 ||
			rt.InfiniteTokenLifetime == nil || rt.GetInfiniteTokenLifetime() != tc.infinite || rt.GetInfiniteIdleTokenLifetime() != tc.infinite {
			t.Fatalf("defaults for %+v = %+v", tc.sent, rt)
		}
	}
	for name, rt := range map[string]*management.ClientRefreshToken{
		"unknown expiration_type": {ExpirationType: auth0.String("never")},
		"empty rotation_type":     {RotationType: auth0.String("")},
		"negative token_lifetime": {TokenLifetime: auth0.Int(-1)},
	} {
		if err := m.Client.Create(ctx, &management.Client{Name: auth0.String("refused"), RefreshToken: rt}); statusOf(err) != http.StatusBadRequest {
			t.Fatalf("create with %s = %v", name, err)
		}
		if err := m.Client.Update(ctx, id, &management.Client{RefreshToken: rt}); statusOf(err) != http.StatusBadRequest {
			t.Fatalf("update with %s = %v", name, err)
		}
	}

	// A client seeded from configuration has no refresh_token; its first one
	// carries Auth0's defaults around what the update sets.
	if err := m.Client.Update(ctx, "mgmt_client_test", &management.Client{RefreshToken: &management.ClientRefreshToken{
		RotationType: auth0.String("rotating"), ExpirationType: auth0.String("expiring"),
	}}); err != nil {
		t.Fatalf("update seeded client: %v", err)
	}
	seeded, err := m.Client.Read(ctx, "mgmt_client_test")
	if err != nil {
		t.Fatalf("read seeded client: %v", err)
	}
	if rt := seeded.GetRefreshToken(); rt.GetRotationType() != "rotating" || rt.GetTokenLifetime() != 2592000 || rt.InfiniteTokenLifetime == nil || rt.GetInfiniteTokenLifetime() {
		t.Fatalf("seeded client refresh_token = %+v", rt)
	}

	// Changing only the expiration type re-derives the infinite flags.
	if err := m.Client.Update(ctx, id, &management.Client{RefreshToken: &management.ClientRefreshToken{ExpirationType: auth0.String("expiring")}}); err != nil {
		t.Fatalf("update expiration_type: %v", err)
	}
	if read, err = m.Client.Read(ctx, id); err != nil || read.GetRefreshToken().GetInfiniteTokenLifetime() || read.GetRefreshToken().GetInfiniteIdleTokenLifetime() {
		t.Fatalf("expiring client keeps infinite lifetimes: %+v %v", read.GetRefreshToken(), err)
	}
}

// Anyone shown an organization's request may refuse it: a non-member's deny
// ends the authorization, which the device then sees as access_denied.
func TestDeviceAuthorizationNonMemberMayDeny(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	other := addOtherOrganization(t, dm)

	issued := issueDeviceAuthorizationForOrganization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid", other)
	approveDevice(t, ts.URL, issued, "deny")
	allowDevicePoll(srv, issued.DeviceCode)
	response, body := deviceTokenRequest(t, ts.URL, deviceClient, issued.DeviceCode)
	if response.StatusCode != http.StatusForbidden || body["error"] != "access_denied" {
		t.Fatalf("poll after a non-member's deny = %d %#v", response.StatusCode, body)
	}
}

// Device sign-ins log as Auth0's do: s at the token exchange, fdecc for a
// refusal, f for a wrong code, fdeac for an unknown user code.
func TestDeviceSignInsReachLogStreams(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	rcv := streamTo(t, srv, ts.URL, "JSONLINES")

	approved := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	approveDevice(t, ts.URL, approved, "approve")
	allowDevicePoll(srv, approved.DeviceCode)
	if response, body := deviceTokenRequest(t, ts.URL, deviceClient, approved.DeviceCode); response.StatusCode != http.StatusOK {
		t.Fatalf("exchange = %d %#v", response.StatusCode, body)
	}
	denied := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	approveDevice(t, ts.URL, denied, "deny")
	wrong := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	for userCode, code := range map[string]string{wrong.UserCode: "000000", "BCDF-GHJK": "123456"} {
		if status, _ := postDevice(t, ts.URL, userCode, "test@example.test", code, "approve"); status != http.StatusBadRequest {
			t.Fatalf("device post %s/%s = %d", userCode, code, status)
		}
	}
	srv.logDeliveries.Wait()

	byType := map[string]logRecord{}
	for _, r := range rcv.records(t, "JSONLINES") {
		byType[r.Data["type"].(string)] = r
	}
	if got := slices.Sorted(maps.Keys(byType)); !slices.Equal(got, []string{"f", "fdeac", "fdecc", "s"}) {
		t.Fatalf("log types = %v", got)
	}
	if s := byType["s"].Data; s["client_id"] != deviceClient || s["connection"] == "" || s["user_id"] != "test_user_1" {
		t.Fatalf("sign-in record = %#v", s)
	}
}

// A malformed identifier, an expired request and a decided one are refused
// before the sign-in can provision a user.
func TestDeviceVerificationRefusesBeforeProvisioning(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	ctx := context.Background()

	malformed := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	expired := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	srv.mu.Lock()
	srv.deviceCodes[expired.DeviceCode].ExpiresAt = time.Now().Add(-time.Second)
	srv.mu.Unlock()
	decided := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	approveDevice(t, ts.URL, decided, "deny")

	for _, tc := range []struct {
		name       string
		issued     deviceAuthorizationResponse
		identifier string
		want       int
	}{
		{"empty identifier", malformed, "", http.StatusBadRequest},
		{"malformed email", malformed, "no@", http.StatusBadRequest},
		{"letters before digits", malformed, "abc5551234567", http.StatusBadRequest},
		{"expired request", expired, "new.person@example.test", http.StatusBadRequest},
		{"decided request", decided, "new.person@example.test", http.StatusConflict},
	} {
		if status, _ := postDevice(t, ts.URL, tc.issued.UserCode, tc.identifier, "123456", "approve"); status != tc.want {
			t.Fatalf("%s = %d, want %d", tc.name, status, tc.want)
		}
	}
	for _, email := range []string{"new.person@example.test", "abc5551234567"} {
		if found, err := dm.User.ListByEmail(ctx, email); err != nil || len(found) != 0 {
			t.Fatalf("a refused post provisioned %s: %d users (%v)", email, len(found), err)
		}
	}
}

// A refresh_token block seeded from configuration reads back with Auth0's
// defaults filled in around what it sets.
func TestSeededClientRefreshTokenReadsComplete(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:   "http://localhost:4646/",
		Audience: "https://api.test",
		Clients: []config.Client{{ClientID: "seeded", Name: "seeded",
			RefreshToken: &config.RefreshTokenConfig{RotationType: config.RefreshTokenRotating, Leeway: 30}}},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	read, err := newMgmt(t, ts.URL).Client.Read(context.Background(), "seeded")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	rt := read.GetRefreshToken()
	if rt.GetRotationType() != "rotating" || rt.GetLeeway() != 30 || rt.GetExpirationType() != "non-expiring" ||
		rt.GetTokenLifetime() != 2592000 || rt.GetIdleTokenLifetime() != 1296000 || !rt.GetInfiniteTokenLifetime() {
		t.Fatalf("seeded refresh_token = %+v", rt)
	}
}

// Posts racing to approve one request with different new identifiers leave one
// approval and one provisioned user: the losers are refused before signing in.
func TestConcurrentDeviceApprovalsProvisionOnce(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")

	const posts = 32
	statuses := make([]int, posts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range posts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses[i], _ = postDevice(t, ts.URL, issued.UserCode, fmt.Sprintf("racer%d@example.test", i), "123456", "approve")
		}()
	}
	close(start)
	wg.Wait()

	approved, provisioned := 0, 0
	for i, status := range statuses {
		if status == http.StatusOK {
			approved++
		} else if status != http.StatusConflict {
			t.Fatalf("post %d = %d, want 200 or 409", i, status)
		}
		found, err := dm.User.ListByEmail(context.Background(), fmt.Sprintf("racer%d@example.test", i))
		if err != nil {
			t.Fatalf("look up racer %d: %v", i, err)
		}
		provisioned += len(found)
	}
	if approved != 1 || provisioned != 1 {
		t.Fatalf("approved %d, provisioned %d; want one of each", approved, provisioned)
	}
}

// An approval is a sign-in, so it counts on the user as one does.
func TestDeviceApprovalRecordsTheLogin(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	ctx := context.Background()
	before, err := dm.User.Read(ctx, "test_user_1")
	if err != nil {
		t.Fatalf("read user: %v", err)
	}

	approveDevice(t, ts.URL, issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid"), "approve")
	after, err := dm.User.Read(ctx, "test_user_1")
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	if after.GetLoginsCount() != before.GetLoginsCount()+1 || after.LastLogin == nil {
		t.Fatalf("logins_count %d -> %d, last_login %v", before.GetLoginsCount(), after.GetLoginsCount(), after.LastLogin)
	}
}

// A request another post is signing in through refuses a second post before
// it provisions anyone.
func TestDeviceVerificationInProgressRefusesAnother(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	srv.mu.Lock()
	srv.deviceCodes[issued.DeviceCode].Verifying = true
	srv.mu.Unlock()

	if status, _ := postDevice(t, ts.URL, issued.UserCode, "second@example.test", "123456", "approve"); status != http.StatusConflict {
		t.Fatalf("post during a verification = %d, want 409", status)
	}
	if found, err := dm.User.ListByEmail(context.Background(), "second@example.test"); err != nil || len(found) != 0 {
		t.Fatalf("the refused post provisioned %d users (%v)", len(found), err)
	}
}

// A refresh may ask for fewer scopes than it was granted, and gets exactly
// those; asking for more is refused.
func TestRefreshNarrowsScope(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	addDeviceClientGrant(t, dm, deviceClient, srv.cfg.Audience, "read:things", "write:things")
	tokens := deviceTokens(t, srv, ts.URL, deviceClient, "openid offline_access read:things write:things")

	bindPostLoginAction(t, dm, "stamp-scopes", `exports.onExecutePostLogin = async (event, api) => {
		api.accessToken.setCustomClaim("https://mock/requested", event.transaction.requested_scopes.join(" "));
	};`)
	narrowed := url.Values{"grant_type": {"refresh_token"}, "client_id": {deviceClient},
		"refresh_token": {tokens["refresh_token"].(string)}, "scope": {"openid read:things"}}
	response, body := postToken(t, ts.URL, narrowed)
	if response.StatusCode != http.StatusOK || body["scope"] != "openid read:things" || claims(t, body["access_token"])["scope"] != "openid read:things" ||
		claims(t, body["access_token"])["https://mock/requested"] != "openid read:things" {
		t.Fatalf("narrowed refresh = %d %#v", response.StatusCode, body)
	}
	narrowed.Set("scope", "   ")
	if response, body := postToken(t, ts.URL, narrowed); response.StatusCode != http.StatusOK || body["scope"] != "openid offline_access read:things write:things" {
		t.Fatalf("blank-scope refresh = %d %#v", response.StatusCode, body)
	}
	narrowed.Set("scope", "openid admin:all")
	if response, body := postToken(t, ts.URL, narrowed); response.StatusCode != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Fatalf("widened refresh = %d %#v", response.StatusCode, body)
	}
}

// A refresh the post-login Action refuses leaves a rotating client's token
// as it was, so the next refresh still works instead of reading as reuse.
func TestRefusedRefreshDoesNotRotate(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	ctx := context.Background()
	deviceClient := addDeviceClient(t, dm, "device_client")
	setRefreshTokenRotation(t, dm, deviceClient, 0)
	refreshToken := deviceTokens(t, srv, ts.URL, deviceClient, "openid offline_access")["refresh_token"].(string)

	bindPostLoginAction(t, dm, "refuse-refresh", `exports.onExecutePostLogin = async (event, api) => { api.access.deny("refused"); };`)
	if response, body := refreshTokenRequest(t, ts.URL, deviceClient, refreshToken); response.StatusCode == http.StatusOK {
		t.Fatalf("refused refresh = %d %#v", response.StatusCode, body)
	}
	if err := dm.Action.UpdateBindings(ctx, "post-login", []*management.ActionBinding{}); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if response, body := refreshTokenRequest(t, ts.URL, deviceClient, refreshToken); response.StatusCode != http.StatusOK || body["refresh_token"] == nil {
		t.Fatalf("refresh after a refusal = %d %#v", response.StatusCode, body)
	}
}

// A retired token presented by another client is refused without revoking the
// family it belongs to.
func TestWrongClientRefreshLeavesFamily(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	otherDeviceClient := addDeviceClient(t, dm, "other_device_client")
	setRefreshTokenRotation(t, dm, deviceClient, 0)
	first := deviceTokens(t, srv, ts.URL, deviceClient, "openid offline_access")["refresh_token"].(string)
	_, rotated := refreshTokenRequest(t, ts.URL, deviceClient, first)
	second, _ := rotated["refresh_token"].(string)
	if second == "" {
		t.Fatalf("no rotation: %#v", rotated)
	}

	for _, client := range []string{otherDeviceClient, ""} {
		if response, body := refreshTokenRequest(t, ts.URL, client, first); response.StatusCode != http.StatusBadRequest {
			t.Fatalf("retired token from client %q = %d %#v", client, response.StatusCode, body)
		}
	}
	if response, body := refreshTokenRequest(t, ts.URL, deviceClient, second); response.StatusCode != http.StatusOK {
		t.Fatalf("family revoked by another client's attempt: %d %#v", response.StatusCode, body)
	}
}

// A request whose application was deleted after the code was issued signs
// no one in on the device page.
func TestDeviceVerificationRefusesIneligibleClient(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	ctx := context.Background()
	deviceClient := addDeviceClient(t, dm, "device_client")
	issued := issueDeviceAuthorization(t, ts.URL, deviceClient, srv.cfg.Audience, "openid")
	if err := dm.Client.Delete(ctx, deviceClient); err != nil {
		t.Fatalf("delete client: %v", err)
	}

	if status, body := postDevice(t, ts.URL, issued.UserCode, "late@example.test", "123456", "approve"); status != http.StatusBadRequest {
		t.Fatalf("post for a deleted client = %d %s", status, body)
	}
	if found, err := dm.User.ListByEmail(ctx, "late@example.test"); err != nil || len(found) != 0 {
		t.Fatalf("provisioned %d users (%v)", len(found), err)
	}
}

// With zero leeway a use of a token whose refresh is still running is reuse:
// refused before its Action runs, and a breach once that refresh succeeds.
func TestConcurrentZeroLeewayRefreshIsReuse(t *testing.T) {
	for _, tc := range []struct {
		name, decision string
		firstStatus    int
		familySurvives bool
	}{
		{"refresh succeeds", "allow", http.StatusForbidden, false},
		{"refresh refused", "deny", http.StatusForbidden, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, ts := setupTestServer(t)
			defer ts.Close()
			dm := newMgmt(t, ts.URL)
			deviceClient := addDeviceClient(t, dm, "device_client")
			setRefreshTokenRotation(t, dm, deviceClient, 0)
			refreshToken := deviceTokens(t, srv, ts.URL, deviceClient, "openid offline_access")["refresh_token"].(string)

			entered := make(chan struct{}, 2)
			proceed := make(chan struct{})
			gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				<-proceed
				_, _ = io.WriteString(w, tc.decision)
			}))
			defer gate.Close()
			bindPostLoginAction(t, dm, "gate", fmt.Sprintf(`exports.onExecutePostLogin = async (event, api) => {
				const response = await fetch(%q);
				if ((await response.text()) === "deny") { api.access.deny("refused"); }
			};`, gate.URL))

			refresh := func() <-chan int {
				done := make(chan int, 1)
				go func() {
					response, _ := refreshTokenRequest(t, ts.URL, deviceClient, refreshToken)
					done <- response.StatusCode
				}()
				return done
			}
			first := refresh()
			<-entered
			second := refresh()
			select {
			case status := <-second:
				if status != http.StatusForbidden {
					t.Fatalf("concurrent refresh = %d", status)
				}
			case <-entered:
				close(proceed)
				t.Fatal("concurrent refresh ran its Action")
			}
			close(proceed)
			if status := <-first; status != tc.firstStatus {
				t.Fatalf("first refresh = %d", status)
			}

			if err := dm.Action.UpdateBindings(context.Background(), "post-login", []*management.ActionBinding{}); err != nil {
				t.Fatalf("unbind: %v", err)
			}
			response, body := refreshTokenRequest(t, ts.URL, deviceClient, refreshToken)
			if survives := response.StatusCode == http.StatusOK; survives != tc.familySurvives {
				t.Fatalf("original token after the overlap = %d %#v", response.StatusCode, body)
			}
		})
	}
}

// Refresh errors are JSON OAuth errors, so an OAuth client reads their code.
func TestRefreshErrorsAreOAuthJSON(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	dm := newMgmt(t, ts.URL)
	deviceClient := addDeviceClient(t, dm, "device_client")
	refreshToken := deviceTokens(t, srv, ts.URL, deviceClient, "openid offline_access")["refresh_token"].(string)

	config := oauth2.Config{ClientID: deviceClient, Endpoint: oauth2.Endpoint{TokenURL: ts.URL + "/oauth/token", AuthStyle: oauth2.AuthStyleInParams}}
	_, err := config.TokenSource(context.Background(), &oauth2.Token{RefreshToken: "rt_unknown"}).Token()
	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) || retrieve.ErrorCode != "invalid_grant" {
		t.Fatalf("unknown refresh token through oauth2 = %v", err)
	}

	response, body := postToken(t, ts.URL, url.Values{"grant_type": {"refresh_token"}, "client_id": {deviceClient},
		"refresh_token": {refreshToken}, "scope": {"openid write:things"}})
	if response.Header.Get("Content-Type") != "application/json" || body["error"] != "invalid_scope" {
		t.Fatalf("widened scope = %q %#v", response.Header.Get("Content-Type"), body)
	}
}
