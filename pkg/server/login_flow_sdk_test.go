package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/authentication"
	"github.com/auth0/go-auth0/authentication/oauth"
	"github.com/auth0/go-auth0/management"
	"golang.org/x/oauth2"

	"github.com/46labs/auth0/pkg/config"
)

// The features consumers reach through the official SDK, exercised through
// it: go-auth0's authentication client (client credentials, code exchange
// with ID token validation, refresh) and its management client (client
// grants, client settings, Actions, organization member roles). The
// authentication client speaks HTTPS only, so these run over TLS.

const sdkAPI = "https://api.sdk.test"

// tlsServerWith is setupTestServerWith served over TLS, with the SDK
// clients built on its certificate.
func tlsServerWith(t *testing.T, edit func(*config.Config)) (*Server, *httptest.Server) {
	t.Helper()
	srv, plain := setupTestServerWith(t, func(cfg *config.Config) {
		cfg.APIs = append(cfg.APIs, config.API{Identifier: sdkAPI, Name: "sdk"})
		cfg.Clients = append(cfg.Clients, config.Client{
			ClientID:                    flowClient,
			AppType:                     "spa",
			GrantTypes:                  []string{"authorization_code", "refresh_token"},
			Callbacks:                   []string{"http://localhost:3000/callback"},
			OrganizationUsage:           orgUsageRequire,
			OrganizationRequireBehavior: orgBehaviorPostLogin,
		})
		if edit != nil {
			edit(cfg)
		}
	})
	plain.Close()
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.cfg.Issuer = ts.URL + "/"
	return srv, ts
}

func sdkAuth(t *testing.T, ts *httptest.Server, clientID, secret string) *authentication.Authentication {
	t.Helper()
	opts := []authentication.Option{authentication.WithClient(ts.Client()), authentication.WithClientID(clientID), authentication.WithNoRetries()}
	if secret != "" {
		opts = append(opts, authentication.WithClientSecret(secret))
	}
	a, err := authentication.New(context.Background(), ts.URL, opts...)
	if err != nil {
		t.Fatalf("authentication client: %v", err)
	}
	return a
}

func sdkManagement(t *testing.T, ts *httptest.Server) *management.Management {
	t.Helper()
	// The SDK fetches its token with the client oauth2 finds in the context.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, ts.Client())
	m, err := management.New(ts.URL, management.WithClientCredentials(ctx, "mgmt_client_dev", "mgmt_secret_dev"),
		management.WithClient(ts.Client()), management.WithNoRetries())
	if err != nil {
		t.Fatalf("management client: %v", err)
	}
	return m
}

func TestSDKClientCredentialsScopes(t *testing.T) {
	_, ts := tlsServerWith(t, func(cfg *config.Config) {
		cfg.ClientGrants = []config.ClientGrant{
			{ClientID: "mgmt_client_dev", Audience: sdkAPI, Scope: []string{"devices:read"}},
			{ClientID: "mgmt_client_dev", Audience: cfg.Audience, Scope: []string{"devices:write"}},
		}
	})
	ctx := context.Background()

	tok, err := sdkAuth(t, ts, "mgmt_client_dev", "mgmt_secret_dev").OAuth.LoginWithClientCredentials(ctx,
		oauth.LoginWithClientCredentialsRequest{Audience: sdkAPI}, oauth.IDTokenValidationOptions{})
	if err != nil {
		t.Fatalf("seeded grant: %v", err)
	}
	if tok.Scope != "devices:read" || claims(t, tok.AccessToken)["scope"] != "devices:read" || claims(t, tok.AccessToken)["gty"] != "client-credentials" {
		t.Fatalf("seeded grant token: %+v", tok)
	}
	// No audience means the default API, whose grant applies.
	def, err := sdkAuth(t, ts, "mgmt_client_dev", "mgmt_secret_dev").OAuth.LoginWithClientCredentials(ctx,
		oauth.LoginWithClientCredentialsRequest{}, oauth.IDTokenValidationOptions{})
	if err != nil {
		t.Fatalf("default audience: %v", err)
	}
	if c := claims(t, def.AccessToken); c["scope"] != "devices:write" {
		t.Fatalf("default audience token: %v", c)
	}
	// Asking for a scope beyond the grant is refused.
	if _, err := sdkAuth(t, ts, "mgmt_client_dev", "mgmt_secret_dev").OAuth.LoginWithClientCredentials(ctx,
		oauth.LoginWithClientCredentialsRequest{Audience: sdkAPI, ExtraParameters: map[string]string{"scope": "devices:read devices:write"}},
		oauth.IDTokenValidationOptions{}); err == nil {
		t.Fatal("scope beyond the grant issued")
	}

	// A grant created through the Management API takes effect at once.
	m := sdkManagement(t, ts)
	if err := m.ClientGrant.Create(ctx, &management.ClientGrant{
		ClientID: auth0.String("mgmt_client_test"), Audience: auth0.String(sdkAPI), Scope: &[]string{"tenants:read", "devices:write"},
	}); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	tok, err = sdkAuth(t, ts, "mgmt_client_test", "mgmt_secret_test").OAuth.LoginWithClientCredentials(ctx,
		oauth.LoginWithClientCredentialsRequest{Audience: sdkAPI}, oauth.IDTokenValidationOptions{})
	if err != nil {
		t.Fatalf("created grant: %v", err)
	}
	if got := claims(t, tok.AccessToken)["scope"]; got != "tenants:read devices:write" {
		t.Fatalf("created grant scope %q", got)
	}
	// A requested subset narrows the token.
	tok, err = sdkAuth(t, ts, "mgmt_client_test", "mgmt_secret_test").OAuth.LoginWithClientCredentials(ctx,
		oauth.LoginWithClientCredentialsRequest{Audience: sdkAPI, ExtraParameters: map[string]string{"scope": "tenants:read"}},
		oauth.IDTokenValidationOptions{})
	if err != nil || claims(t, tok.AccessToken)["scope"] != "tenants:read" {
		t.Fatalf("narrowed: %v %v", err, tok)
	}
}

// sdkFlow drives the login page (no SDK has one) and exchanges and
// refreshes through the SDK, which validates every ID token.
func sdkFlow(t *testing.T, ts *httptest.Server, extra string) *flow {
	t.Helper()
	return startFlow(t, ts, flowClient, extra)
}

func sdkExchange(t *testing.T, ts *httptest.Server, f *flow, loc *url.URL, org string) *oauth.TokenSet {
	t.Helper()
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code in %s", loc)
	}
	tok, err := sdkAuth(t, ts, flowClient, "").OAuth.LoginWithAuthCodeWithPKCE(context.Background(), oauth.LoginWithAuthCodeWithPKCERequest{
		Code: loc.Query().Get("code"), CodeVerifier: f.verifier, RedirectURI: "http://localhost:3000/callback",
	}, oauth.IDTokenValidationOptions{Organization: org})
	if err != nil {
		t.Fatalf("SDK code exchange: %v", err)
	}
	return tok
}

func TestSDKOrganizationPromptSecondFactorAndRoles(t *testing.T) {
	_, ts := tlsServerWith(t, func(cfg *config.Config) {
		cfg.Organizations = append(cfg.Organizations, config.Organization{ID: "org_second", Name: "second", DisplayName: "Second"})
		for i := range cfg.Connections {
			cfg.Connections[i].Organizations = append(cfg.Connections[i].Organizations, "org_second")
		}
		cfg.Members = append(cfg.Members, config.OrganizationMember{UserID: "test_user_1", OrgID: "org_second"})
		cfg.Roles = append(cfg.Roles, config.Role{ID: "rol_owner", Name: "app-owner"})
	})
	ctx := context.Background()
	m := sdkManagement(t, ts)

	// The member's role in the organization, assigned through the SDK.
	if err := m.Organization.AssignMemberRoles(ctx, "org_second", "test_user_1", []string{"rol_owner"}); err != nil {
		t.Fatalf("assign member role: %v", err)
	}
	bindPostLoginAction(t, m, "second-factor-and-roles", `
		exports.onExecutePostLogin = async (event, api) => {
		  const mfa = event.authentication.methods.some((x) => x.name === 'mfa');
		  if (!mfa && event.transaction.protocol !== 'oauth2-refresh-token') {
		    api.multifactor.enable('any', { allowRememberBrowser: false });
		  }
		  api.accessToken.setCustomClaim('https://sdk/roles', event.authorization.roles);
		  api.accessToken.setCustomClaim('https://sdk/mfa', mfa);
		};`)

	f := sdkFlow(t, ts, "&audience="+url.QueryEscape(sdkAPI))
	status, body, _ := f.signIn("+14155551234")
	if status != http.StatusOK || !strings.Contains(body, "Choose an organization") {
		t.Fatalf("picker: %d %s", status, body)
	}
	status, body, _ = f.post(url.Values{"organization": {"org_second"}})
	if status != http.StatusOK || !strings.Contains(body, `name="mfa_code"`) {
		t.Fatalf("second factor: %d %s", status, body)
	}
	status, _, loc := f.post(url.Values{"mfa_code": {passwordlessCode}})
	if status != http.StatusFound {
		t.Fatalf("after second factor: %d", status)
	}

	tok := sdkExchange(t, ts, f, loc, "org_second")
	access := claims(t, tok.AccessToken)
	if access["org_id"] != "org_second" || access["https://sdk/mfa"] != false {
		t.Fatalf("access token: %v", access)
	}
	if roles, _ := access["https://sdk/roles"].([]any); len(roles) != 1 || roles[0] != "app-owner" {
		t.Fatalf("organization roles %v, want [app-owner]", access["https://sdk/roles"])
	}

	refreshed, err := sdkAuth(t, ts, flowClient, "").OAuth.RefreshToken(ctx, oauth.RefreshTokenRequest{RefreshToken: tok.RefreshToken},
		oauth.IDTokenValidationOptions{Organization: "org_second"})
	if err != nil {
		t.Fatalf("SDK refresh: %v", err)
	}
	if c := claims(t, refreshed.AccessToken); c["https://sdk/mfa"] != false || c["org_id"] != "org_second" {
		t.Fatalf("refreshed: %v", c)
	}
}

func TestSDKClientOrganizationSettingsDriveLogin(t *testing.T) {
	_, ts := tlsServerWith(t, nil)
	ctx := context.Background()
	m := sdkManagement(t, ts)

	// no_prompt through the SDK: a login that names no organization is
	// refused with Auth0's error.
	if err := m.Client.Update(ctx, flowClient, &management.Client{OrganizationRequireBehavior: auth0.String("no_prompt")}); err != nil {
		t.Fatalf("update: %v", err)
	}
	c, err := m.Client.Read(ctx, flowClient)
	if err != nil || c.GetOrganizationUsage() != "require" || c.GetOrganizationRequireBehavior() != "no_prompt" {
		t.Fatalf("read back: %v %+v", err, c)
	}
	if loc := authorizeRedirect(t, ts, flowClient, ""); loc.Query().Get("error_description") != errOrganizationMissing {
		t.Fatalf("no_prompt: %s", loc)
	}

	// Named organization still signs in, and the SDK validates its ID token
	// for that organization.
	f := sdkFlow(t, ts, "&organization=org_test")
	_, _, loc := f.signIn("+14155551234")
	if tok := sdkExchange(t, ts, f, loc, "org_test"); claims(t, tok.IDToken)["org_id"] != "org_test" {
		t.Fatalf("id token org: %v", claims(t, tok.IDToken))
	}
}

func TestSDKClientCreateValidatesOrganizationSettings(t *testing.T) {
	_, ts := tlsServerWith(t, nil)
	ctx := context.Background()
	m := sdkManagement(t, ts)
	for _, c := range []*management.Client{
		{Name: auth0.String("bad usage"), OrganizationUsage: auth0.String("required")},
		{Name: auth0.String("pre-login"), OrganizationUsage: auth0.String("require"), OrganizationRequireBehavior: auth0.String("pre_login_prompt")},
	} {
		if err := m.Client.Create(ctx, c); err == nil {
			t.Fatalf("created %s", c.GetName())
		}
	}
	if err := m.Client.Create(ctx, &management.Client{Name: auth0.String("empty"), OrganizationUsage: auth0.String("")}); err == nil {
		t.Fatal("created with an empty organization_usage")
	}
	ok := &management.Client{Name: auth0.String("ok"), OrganizationUsage: auth0.String("require"), OrganizationRequireBehavior: auth0.String("post_login_prompt")}
	if err := m.Client.Create(ctx, ok); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got, err := m.Client.Read(ctx, ok.GetClientID()); err != nil || got.GetOrganizationRequireBehavior() != "post_login_prompt" {
		t.Fatalf("read back: %v %+v", err, got)
	}
}

func TestConfigRejectsBadClientsAndDuplicateGrants(t *testing.T) {
	for name, edit := range map[string]func(*config.Config){
		"duplicate grant": func(cfg *config.Config) {
			g := config.ClientGrant{ClientID: "mgmt_client_dev", Audience: sdkAPI, Scope: []string{"a"}}
			cfg.ClientGrants = []config.ClientGrant{g, g}
		},
		"bad organization usage": func(cfg *config.Config) {
			cfg.Clients[0].OrganizationUsage = "required"
		},
		"grant for an unknown client": func(cfg *config.Config) {
			cfg.ClientGrants = []config.ClientGrant{{ClientID: "typo", Audience: sdkAPI}}
		},
		"grant for an unknown API": func(cfg *config.Config) {
			cfg.ClientGrants = []config.ClientGrant{{ClientID: "mgmt_client_dev", Audience: "https://typo.test"}}
		},
		"grant without an audience": func(cfg *config.Config) {
			cfg.ClientGrants = []config.ClientGrant{{ClientID: "mgmt_client_dev"}}
		},
	} {
		cfg := &config.Config{Issuer: "http://localhost/", Audience: "http://localhost:3000", Clients: []config.Client{{ClientID: "mgmt_client_dev"}}}
		edit(cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: server started", name)
		}
	}
}

func TestSDKClientOrganizationNullAndOIDC(t *testing.T) {
	_, ts := tlsServerWith(t, nil)
	ctx := context.Background()
	m := sdkManagement(t, ts)
	// post_login_prompt needs an OIDC-conformant client.
	if err := m.Client.Update(ctx, flowClient, &management.Client{OIDCConformant: auth0.Bool(false)}); err == nil {
		t.Fatal("post_login_prompt client made non-conformant")
	}
	// null resets a setting; the typed Client cannot send null, so through
	// the SDK's raw request.
	if err := m.Request(ctx, http.MethodPatch, m.URI("clients", flowClient),
		map[string]any{"organization_usage": nil, "organization_require_behavior": nil}); err != nil {
		t.Fatalf("null patch: %v", err)
	}
	c, err := m.Client.Read(ctx, flowClient)
	if err != nil || c.GetOrganizationUsage() != "" || c.GetOrganizationRequireBehavior() != "" {
		t.Fatalf("null reset: %v %q %q", err, c.GetOrganizationUsage(), c.GetOrganizationRequireBehavior())
	}
}
