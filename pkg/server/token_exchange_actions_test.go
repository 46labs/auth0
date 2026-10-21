package server

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/46labs/auth0/pkg/config"
	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
	"github.com/golang-jwt/jwt/v5"
)

// exchangeAction verifies the subject token the way a real Action does, with
// jsonwebtoken and jwks-rsa, then hands the exchange to the body's target.
const exchangeAction = `
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
exports.onExecuteCustomTokenExchange = async (event, api) => {
  const client = jwksClient({ jwksUri: 'https://auth.example.test/.well-known/jwks.json' });
  const getKey = (header, cb) => client.getSigningKey(header.kid, (err, key) => cb(err, key && key.getPublicKey()));
  let claims;
  try {
    claims = await new Promise((resolve, reject) =>
      jwt.verify(event.transaction.subject_token, getKey,
        { algorithms: ['RS256'], issuer: 'https://auth.example.test/', audience: event.resource_server.identifier },
        (err, decoded) => (err ? reject(err) : resolve(decoded))));
  } catch (e) {
    api.access.rejectInvalidSubjectToken('verify failed: ' + e.message);
    return;
  }
  if (event.request.body.refuse) {
    api.access.deny('forbidden', 'refused by the action');
    return;
  }
  api.transaction.setMetadata('target', event.request.body.target_user);
  api.authentication.setUserById(event.request.body.target_user || claims.sub);
  if (event.request.body.target_org) api.authentication.setOrganization(event.request.body.target_org);
  api.authentication.setActor({ sub: claims.sub });
};`

// actorClaims copies what post-login sees of the exchange onto the token.
const actorClaims = `
exports.onExecutePostLogin = async (event, api) => {
  api.accessToken.setCustomClaim('https://mock/actor', event.transaction.actor && event.transaction.actor.sub);
  api.accessToken.setCustomClaim('https://mock/target', event.transaction.metadata && event.transaction.metadata.target);
  api.accessToken.setCustomClaim('https://mock/proto', event.transaction.protocol);
  api.accessToken.setCustomClaim('https://mock/org', event.organization && event.organization.id);
  api.accessToken.setCustomClaim('https://mock/saw-subject-token', 'subject_token' in event.request.body);
};`

// exchangeDeps are what the exchange Action declares; Auth0 installs nothing else.
var exchangeDeps = []string{"jsonwebtoken", "jwks-rsa"}

func actionExchangeServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{
		Issuer:        "https://auth.example.test/",
		Audience:      "https://api.example.test",
		Organizations: []config.Organization{{ID: "org_1", Name: "org-one"}, {ID: "org_2", Name: "org-two"}},
		Clients:       []config.Client{{ClientID: "spa_app"}, {ClientID: "other_app"}},
		Connections: []config.Connection{
			{ID: "con_email", Name: "email", Strategy: "email", EnabledClients: []string{"spa_app"}, Organizations: []string{"org_1", "org_2"}},
		},
		Users: []config.User{
			{ID: "email|admin", Email: "admin@example.test", Identities: []config.UserIdentity{{Connection: "email", Provider: "email", UserID: "admin"}}},
			{ID: "email|member", Email: "member@example.test", Identities: []config.UserIdentity{{Connection: "email", Provider: "email", UserID: "member"}}},
			{ID: "email|bare", Email: "bare@example.test"},
			{ID: "gone|user", Email: "gone@example.test", Identities: []config.UserIdentity{{Connection: "gone", Provider: "oidc", UserID: "user"}}},
		},
		Members: []config.OrganizationMember{{UserID: "email|member", OrgID: "org_1"}},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ctx := t.Context()
	m, err := management.New(ts.URL, management.WithStaticToken("mgmt"), management.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	deploy := func(name, code, trigger, version string, deps ...string) string {
		a := &management.Action{
			Name: auth0.String(name), Code: auth0.String(code), Runtime: auth0.String("node22"),
			SupportedTriggers: []management.ActionTrigger{{ID: auth0.String(trigger), Version: auth0.String(version)}},
		}
		declared := []management.ActionDependency{}
		for _, d := range deps {
			declared = append(declared, management.ActionDependency{Name: auth0.String(d), Version: auth0.String("1.0.0")})
		}
		a.Dependencies = &declared
		if err := m.Action.Create(ctx, a); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := m.Action.Deploy(ctx, a.GetID()); err != nil {
			t.Fatalf("deploy %s: %v", name, err)
		}
		return a.GetID()
	}
	if err := m.TokenExchangeProfile.Create(ctx, &management.TokenExchangeProfile{
		Name: auth0.String("exchange"), Type: auth0.String("custom_authentication"),
		SubjectTokenType: auth0.String(exSubjectType), ActionID: auth0.String(deploy("exchange", exchangeAction, "custom-token-exchange", "v1", exchangeDeps...)),
	}); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	deploy("actor-claims", actorClaims, "post-login", "v3")
	if err := m.Action.UpdateBindings(ctx, "post-login", []*management.ActionBinding{{
		Ref: &management.ActionBindingReference{Type: auth0.String("action_name"), Value: auth0.String("actor-claims")}, DisplayName: auth0.String("actor-claims"),
	}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return srv, ts
}

func actionExchange(t *testing.T, srv *Server, ts *httptest.Server, subject string, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("grant_type", tokenExchangeGrantType)
	form.Set("subject_token", subject)
	form.Set("subject_token_type", exSubjectType)
	if form.Get("client_id") == "" {
		form.Set("client_id", "spa_app")
	}
	resp, err := ts.Client().PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func adminSubject(t *testing.T, srv *Server) string {
	return srv.signSubject(t, jwt.MapClaims{"sub": "email|admin", "aud": "https://api.example.test"})
}

func TestExchangeAction_ViewAsTheTarget(t *testing.T) {
	srv, ts := actionExchangeServer(t)
	st, out := actionExchange(t, srv, ts, adminSubject(t, srv), url.Values{"target_user": {"email|member"}, "target_org": {"org_1"}, "scope": {"openid read:calls"}})
	if st != 200 {
		t.Fatalf("exchange: %d %v", st, out)
	}
	c := claims(t, out["access_token"])
	if c["sub"] != "email|member" || c["org_id"] != "org_1" || c["aud"] != "https://api.example.test" {
		t.Fatalf("token: %v", c)
	}
	if c["https://mock/saw-subject-token"] != false {
		t.Fatal("post-login saw the source bearer token")
	}
	if c["scope"] != "openid read:calls" {
		t.Fatalf("scope: %v", c["scope"])
	}
	if act, _ := c["act"].(map[string]any); act["sub"] != "email|admin" {
		t.Fatalf("act: %v", c["act"])
	}
	// Post-login ran as the target and saw the exchange's actor and metadata.
	if c["https://mock/actor"] != "email|admin" || c["https://mock/target"] != "email|member" ||
		c["https://mock/proto"] != "oauth2-token-exchange" || c["https://mock/org"] != "org_1" {
		t.Fatalf("post-login: %v", c)
	}
}

func TestExchangeAction_Refusals(t *testing.T) {
	srv, ts := actionExchangeServer(t)
	admin := adminSubject(t, srv)
	foreign := srv.signSubject(t, jwt.MapClaims{"sub": "email|admin", "aud": "https://other.example.test"})

	cases := []struct {
		name, subject string
		form          url.Values
		code, desc    string
	}{
		{"malformed subject", "invalid", url.Values{}, "invalid_request", "verify failed: jwt malformed"},
		{"subject for another API", foreign, url.Values{}, "invalid_request", "verify failed: jwt audience invalid. expected: https://api.example.test"},
		{"action denies", admin, url.Values{"refuse": {"1"}}, "forbidden", "refused by the action"},
		{"connection not enabled for the client", admin, url.Values{"client_id": {"other_app"}}, "invalid_request", "Unknown connection (email) for client other_app."},
		{"target not a member", admin, url.Values{"target_user": {"email|member"}, "target_org": {"org_2"}}, "invalid_request", "user does not belong to the organization"},
		{"unknown organization", admin, url.Values{"target_user": {"email|member"}, "target_org": {"org_x"}}, "invalid_request", "Organization not found"},
		{"unknown user", admin, url.Values{"target_user": {"email|nobody"}}, "invalid_request", "user not found"},
		{"user without an identity", admin, url.Values{"target_user": {"email|bare"}}, "invalid_request", "user has no identity"},
		{"identity on a missing connection", admin, url.Values{"target_user": {"gone|user"}}, "invalid_request", "Unknown connection (gone) for client spa_app."},
	}
	t.Run("unknown client", func(t *testing.T) {
		st, out := actionExchange(t, srv, ts, admin, url.Values{"client_id": {"nobody_app"}})
		if st != 401 || out["error"] != "invalid_client" {
			t.Fatalf("got %d %v, want 401 invalid_client", st, out)
		}
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, out := actionExchange(t, srv, ts, tc.subject, tc.form)
			desc, _ := out["error_description"].(string)
			if st != 400 || out["error"] != tc.code || !strings.Contains(desc, tc.desc) {
				t.Fatalf("got %d %v, want 400 %s %q", st, out, tc.code, tc.desc)
			}
		})
	}
}

// The drop-in sets no organization; post-login must not be handed one from the
// user's metadata, or an Action that scopes by its absence never does.
func TestExchangeAction_NoOrganizationStaysUnset(t *testing.T) {
	srv, ts := actionExchangeServer(t)
	srv.mu.Lock()
	srv.users["email|admin"].AppMetadata = config.AppMetadata{"tenant_id": "org_1"}
	srv.mu.Unlock()
	st, out := actionExchange(t, srv, ts, adminSubject(t, srv), url.Values{})
	if st != 200 {
		t.Fatalf("exchange: %d %v", st, out)
	}
	if c := claims(t, out["access_token"]); c["org_id"] != nil || c["https://mock/org"] != nil {
		t.Fatalf("an organization appeared: %v", c)
	}
}

func TestExchangeAction_ProfileTakesPrecedenceOverTheStandIn(t *testing.T) {
	srv, ts := actionExchangeServer(t)
	srv.cfg.Actions.TokenExchange = &config.TokenExchangeAction{SubjectTokenType: exSubjectType}
	st, out := actionExchange(t, srv, ts, adminSubject(t, srv), url.Values{"target_user": {"email|member"}, "target_org": {"org_1"}})
	if st != 200 || claims(t, out["access_token"])["sub"] != "email|member" {
		t.Fatalf("exchange: %d %v", st, out)
	}
}

// Auth0 installs only declared dependencies; an Action that requires an
// undeclared one fails rather than finding it.
func TestExchangeAction_UndeclaredDependencyFails(t *testing.T) {
	srv, ts := actionExchangeServer(t)
	m, err := management.New(ts.URL, management.WithStaticToken("mgmt"), management.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	list, err := m.TokenExchangeProfile.List(ctx)
	if err != nil || len(list.TokenExchangeProfiles) != 1 {
		t.Fatalf("profiles: %v %v", list, err)
	}
	if err := m.Action.Update(ctx, list.TokenExchangeProfiles[0].GetActionID(), &management.Action{Dependencies: &[]management.ActionDependency{}}); err != nil {
		t.Fatalf("drop dependencies: %v", err)
	}
	if _, err := m.Action.Deploy(ctx, list.TokenExchangeProfiles[0].GetActionID()); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	st, out := actionExchange(t, srv, ts, adminSubject(t, srv), url.Values{})
	if desc, _ := out["error_description"].(string); st != 400 || !strings.Contains(desc, "jsonwebtoken") {
		t.Fatalf("got %d %v, want the require to fail", st, out)
	}
}
