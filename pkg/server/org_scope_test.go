package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/46labs/auth0/pkg/config"
	"github.com/auth0/go-auth0/management"
)

// loginToOrg drives an ordinary (non-invitation) login scoped to an
// organization via the `organization` authorize parameter, and returns the
// token response or the refusal.
func loginToOrg(t *testing.T, baseURL, identifier, orgID, scope string) (*acceptedTokens, int, string) {
	t.Helper()

	client := noRedirectClient()

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "test_client")
	params.Set("redirect_uri", testRedirectURI)
	params.Set("scope", scope)
	if orgID != "" {
		params.Set("organization", orgID)
	}

	resp, err := client.Get(baseURL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		loc, _ := url.Parse(resp.Header.Get("Location"))
		return nil, resp.StatusCode, loc.Query().Get("error_description")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, string(body)
	}

	m := sessionIDRe.FindStringSubmatch(string(body))
	if len(m) < 2 {
		t.Fatal("no session_id in login page")
	}

	resp2, err := client.PostForm(baseURL+"/authorize", url.Values{
		"session_id": {m[1]},
		"identifier": {identifier},
		"code":       {"123456"},
	})
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusFound {
		return nil, resp2.StatusCode, strings.TrimSpace(string(body2))
	}

	loc, _ := url.Parse(resp2.Header.Get("Location"))
	authCode := loc.Query().Get("code")
	if authCode == "" {
		return nil, resp2.StatusCode, "no code: " + resp2.Header.Get("Location")
	}

	resp3, err := client.PostForm(baseURL+"/oauth/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode},
		"client_id":    {"test_client"},
		"redirect_uri": {testRedirectURI},
	})
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		return nil, resp3.StatusCode, strings.TrimSpace(string(body3))
	}

	var tokens acceptedTokens
	if err := decodeJSON(body3, &tokens); err != nil {
		t.Fatalf("token response not JSON: %v (%s)", err, body3)
	}
	return &tokens, resp3.StatusCode, ""
}

// TestOrgScopedLoginRequiresMembership is the authorization gate on the
// `organization` parameter. Without it, any caller could name an arbitrary
// organization on /authorize and be handed a token carrying its org_id —
// potentially with a role inherited from somewhere else entirely.
func TestOrgScopedLoginRequiresMembership(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	other := "outsider-org"
	otherOrg := &management.Organization{Name: &other}
	if err := f.m.Organization.Create(ctx, otherOrg); err != nil {
		t.Fatalf("Organization.Create: %v", err)
	}

	t.Run("MemberIsAllowed", func(t *testing.T) {
		// test_user_1 is a seeded member of org_test.
		tokens, status, msg := loginToOrg(t, f.ts.URL, "+14155551234", "org_test", "openid")
		if tokens == nil {
			t.Fatalf("a member was refused: %d %s", status, msg)
		}
		access := claimsOf(t, f.srv, tokens.AccessToken)
		if access["org_id"] != "org_test" {
			t.Errorf("org_id = %v, want org_test", access["org_id"])
		}
	})

	t.Run("NonMemberIsRefused", func(t *testing.T) {
		tokens, _, msg := loginToOrg(t, f.ts.URL, "+14155551234", otherOrg.GetID(), "openid")
		if tokens != nil {
			t.Fatal("a non-member was issued a token for the organization")
		}
		if !strings.Contains(msg, "not a member") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})

	t.Run("UnknownOrganizationIsRefused", func(t *testing.T) {
		tokens, _, msg := loginToOrg(t, f.ts.URL, "+14155551234", "org_does_not_exist", "openid")
		if tokens != nil {
			t.Fatal("a token was issued for an organization that does not exist")
		}
		if !strings.Contains(msg, "does not exist") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})

	t.Run("AssignMembershipOnLoginGrantsAccess", func(t *testing.T) {
		// Auth0's escape hatch: a connection that grants membership on login.
		assign := true
		if err := f.m.Organization.AddConnection(ctx, otherOrg.GetID(),
			&management.OrganizationConnection{
				ConnectionID:            &f.connectionID,
				AssignMembershipOnLogin: &assign,
			}); err != nil {
			t.Fatalf("Organization.AddConnection: %v", err)
		}

		tokens, status, msg := loginToOrg(t, f.ts.URL, "+14155551234", otherOrg.GetID(), "openid")
		if tokens == nil {
			t.Fatalf("assign_membership_on_login should admit a non-member: %d %s", status, msg)
		}
		access := claimsOf(t, f.srv, tokens.AccessToken)
		if access["org_id"] != otherOrg.GetID() {
			t.Errorf("org_id = %v, want %s", access["org_id"], otherOrg.GetID())
		}

		// And membership was actually granted.
		found := false
		for _, m := range f.srv.GetOrgMembers(otherOrg.GetID()) {
			if m.UserID == "test_user_1" {
				found = true
			}
		}
		if !found {
			t.Error("membership was not granted despite assign_membership_on_login")
		}
	})
}

// TestLegacyRoleDoesNotLeakAcrossOrgs covers the role-scoping rule: the flat
// app_metadata.role belongs to app_metadata.tenant_id, so it must not be
// emitted for a different organization. Otherwise an admin of one tenant
// carries that role into every organization they log in to.
func TestLegacyRoleDoesNotLeakAcrossOrgs(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	// A second org this user is a member of, with no role assigned.
	second := "roleless-org"
	secondOrg := &management.Organization{Name: &second}
	if err := f.m.Organization.Create(ctx, secondOrg); err != nil {
		t.Fatalf("Organization.Create: %v", err)
	}
	if err := f.m.Organization.AddMembers(ctx, secondOrg.GetID(), []string{"test_user_1"}); err != nil {
		t.Fatalf("Organization.AddMembers: %v", err)
	}

	// test_user_1 carries app_metadata {tenant_id: org_test, role: admin}.
	tokens, status, msg := loginToOrg(t, f.ts.URL, "+14155551234", secondOrg.GetID(), "openid")
	if tokens == nil {
		t.Fatalf("member login refused: %d %s", status, msg)
	}

	roleClaim := strings.TrimSuffix(f.srv.cfg.Issuer, "/") + "/role"
	access := claimsOf(t, f.srv, tokens.AccessToken)

	if access["org_id"] != secondOrg.GetID() {
		t.Errorf("org_id = %v, want %s", access["org_id"], secondOrg.GetID())
	}
	if got, present := access[roleClaim]; present && got == "admin" {
		t.Errorf("the org_test admin role leaked into %s", secondOrg.GetID())
	}
}

// TestRefreshTokenKeepsItsOrganization covers the refresh binding: an
// offline_access login scoped to one organization must keep coming back for
// that organization, not re-derive org_id from whatever app_metadata says
// later.
func TestRefreshTokenKeepsItsOrganization(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	second := "refresh-org"
	secondOrg := &management.Organization{Name: &second}
	if err := f.m.Organization.Create(ctx, secondOrg); err != nil {
		t.Fatalf("Organization.Create: %v", err)
	}
	if err := f.m.Organization.AddMembers(ctx, secondOrg.GetID(), []string{"test_user_1"}); err != nil {
		t.Fatalf("Organization.AddMembers: %v", err)
	}

	// Log in scoped to the second organization, asking for a refresh token.
	tokens, status, msg := loginToOrg(t, f.ts.URL, "+14155551234", secondOrg.GetID(), "openid offline_access")
	if tokens == nil {
		t.Fatalf("login refused: %d %s", status, msg)
	}

	// Grab the refresh token from a fresh exchange (loginToOrg discards it),
	// then move the user's stored tenant somewhere else entirely.
	refresh := refreshTokenFor(t, f, "test_user_1", secondOrg.GetID())

	appMeta := map[string]any{"tenant_id": "org_test", "role": "admin"}
	if err := f.m.User.Update(ctx, "test_user_1", &management.User{AppMetadata: &appMeta}); err != nil {
		t.Fatalf("User.Update: %v", err)
	}

	resp, err := http.PostForm(f.ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {"test_client"},
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh returned %d: %s", resp.StatusCode, body)
	}

	var refreshed acceptedTokens
	if err := decodeJSON(body, &refreshed); err != nil {
		t.Fatalf("refresh response not JSON: %v", err)
	}

	access := claimsOf(t, f.srv, refreshed.AccessToken)
	if access["org_id"] != secondOrg.GetID() {
		t.Errorf("refreshed org_id = %v, want the original %s", access["org_id"], secondOrg.GetID())
	}
}

// refreshTokenFor mints a refresh token for a user in an organization by
// exchanging an offline_access code, and returns it.
func refreshTokenFor(t *testing.T, f *inviteFixture, userID, orgID string) string {
	t.Helper()

	code := f.srv.IssueAuthCode(userID, "openid offline_access", orgID, "test_client")
	if code == "" {
		t.Fatalf("could not issue a code for %s", userID)
	}

	resp, err := http.PostForm(f.ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
		"client_id":  {"test_client"},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var out struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(body, &out); err != nil {
		t.Fatalf("exchange response not JSON: %v", err)
	}
	if out.RefreshToken == "" {
		t.Fatalf("no refresh token issued: %s", body)
	}
	return out.RefreshToken
}

// TestPostLoginActionUsesSelectedOrg covers the action context: for a user in
// several organizations, ${authorization.role} must resolve against the one
// the login selected, not the user's stored tenant_id.
func TestPostLoginActionUsesSelectedOrg(t *testing.T) {
	cfg := &config.Config{
		Issuer:   "https://auth.example.test/",
		Audience: "https://api.example.test",
		Users: []config.User{{
			ID:    "auth0|multi",
			Email: "multi@example.test",
			Name:  "Multi Org",
			AppMetadata: config.AppMetadata{
				config.AppMetaTenantID: "org_first",
				config.AppMetaRole:     "admin",
			},
		}},
		Organizations: []config.Organization{
			{ID: "org_first", Name: "first"},
			{ID: "org_second", Name: "second"},
		},
		Members: []config.OrganizationMember{
			{UserID: "auth0|multi", OrgID: "org_first", Role: "admin"},
			{UserID: "auth0|multi", OrgID: "org_second", Role: "viewer"},
		},
		Clients: []config.Client{{ClientID: "test_client", Name: "Test"}},
		Actions: config.Actions{PostLogin: &config.PostLoginAction{
			AccessTokenClaims: map[string]string{
				"role":   "${authorization.role}",
				"org_id": "${authorization.org_id}",
			},
		}},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Log in scoped to the second organization, where the role is viewer.
	code := srv.IssueAuthCode("auth0|multi", "openid", "org_second", "test_client")
	resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
		"client_id":  {"test_client"},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var out acceptedTokens
	if err := decodeJSON(body, &out); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, body)
	}

	ns := strings.TrimSuffix(srv.cfg.Issuer, "/") + "/"
	claims := claimsOf(t, srv, out.AccessToken)

	if claims[ns+"org_id"] != "org_second" {
		t.Errorf("action org_id = %v, want org_second", claims[ns+"org_id"])
	}
	if claims[ns+"role"] != "viewer" {
		t.Errorf("action role = %v, want viewer (the selected org's role, not the stored tenant's)",
			claims[ns+"role"])
	}
}

// decodeJSON unmarshals a token response body.
func decodeJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
