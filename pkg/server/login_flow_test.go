package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"

	"github.com/46labs/auth0/pkg/config"
)

const flowClient = "flow_spa"

var sessionField = regexp.MustCompile(`name="session_id" value="([^"]*)"`)

// flowServer is the test server with a SPA client that requires an
// organization and prompts after sign-in, and a second organization.
func flowServer(t *testing.T, behavior string) *httptest.Server {
	t.Helper()
	_, ts := setupTestServerWith(t, func(cfg *config.Config) {
		cfg.Clients = append(cfg.Clients, config.Client{
			ClientID:                    flowClient,
			AppType:                     "spa",
			GrantTypes:                  []string{"authorization_code", "refresh_token"},
			Callbacks:                   []string{"http://localhost:3000/callback"},
			OrganizationUsage:           orgUsageRequire,
			OrganizationRequireBehavior: behavior,
		})
		cfg.Organizations = append(cfg.Organizations, config.Organization{ID: "org_second", Name: "second", DisplayName: "Second"})
		for i := range cfg.Connections {
			cfg.Connections[i].Organizations = append(cfg.Connections[i].Organizations, "org_second")
		}
		cfg.Members = append(cfg.Members, config.OrganizationMember{UserID: "test_user_1", OrgID: "org_second", Role: "admin"})
	})
	t.Cleanup(ts.Close)
	return ts
}

// flow drives the login page by hand: each step returns the response.
type flow struct {
	t        *testing.T
	ts       *httptest.Server
	hc       *http.Client
	page     string
	verifier string
}

func startFlow(t *testing.T, ts *httptest.Server, client, extra string) *flow {
	t.Helper()
	verifier, challenge := generatePKCE()
	// A copy of the server's own client, which trusts its certificate when
	// it serves TLS; the server's is shared.
	base := *ts.Client()
	hc := &base
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f := &flow{t: t, ts: ts, verifier: verifier, hc: hc}
	q := url.Values{
		"response_type": {"code"}, "client_id": {client}, "redirect_uri": {"http://localhost:3000/callback"},
		"scope": {"openid offline_access"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"state": {"st"},
	}
	resp, err := f.hc.Get(ts.URL + "/authorize?" + q.Encode() + extra)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := sessionField.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("no login page: %d %s", resp.StatusCode, body)
	}
	f.page = m[1]
	return f
}

func (f *flow) post(form url.Values) (int, string, *url.URL) {
	f.t.Helper()
	form.Set("session_id", f.page)
	resp, err := f.hc.PostForm(f.ts.URL+"/authorize", form)
	if err != nil {
		f.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return resp.StatusCode, string(body), loc
}

func (f *flow) signIn(phone string) (int, string, *url.URL) {
	return f.post(url.Values{"phone": {phone}, "code": {passwordlessCode}})
}

func (f *flow) exchange(client string, loc *url.URL) map[string]any {
	f.t.Helper()
	if loc.Query().Get("code") == "" {
		f.t.Fatalf("no code in %s", loc)
	}
	resp, err := f.hc.PostForm(f.ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {client}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"http://localhost:3000/callback"}, "code_verifier": {f.verifier},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("exchange: %d %v", resp.StatusCode, out)
	}
	return out
}

func TestOrganizationPromptAfterLogin(t *testing.T) {
	ts := flowServer(t, orgBehaviorPostLogin)

	// Two memberships: the picker lists both.
	f := startFlow(t, ts, flowClient, "")
	status, body, _ := f.signIn("+14155551234")
	if status != http.StatusOK || !strings.Contains(body, "Choose an organization") ||
		!strings.Contains(body, `value="org_test"`) || !strings.Contains(body, `value="org_second"`) {
		t.Fatalf("picker: %d %s", status, body)
	}
	if st, _, _ := f.post(url.Values{"organization": {"org_unknown"}}); st != http.StatusBadRequest {
		t.Fatalf("a non-member organization: %d", st)
	}
	status, _, loc := f.post(url.Values{"organization": {"org_second"}})
	if status != http.StatusFound || loc.Query().Get("state") != "st" {
		t.Fatalf("choose: %d %s", status, loc)
	}
	tok := f.exchange(flowClient, loc)
	if org := claims(t, tok["access_token"])["org_id"]; org != "org_second" {
		t.Fatalf("org_id %v, want org_second", org)
	}

	// One membership signs straight in.
	f = startFlow(t, ts, flowClient, "")
	status, _, loc = f.post(url.Values{"email": {"email@example.test"}, "code": {passwordlessCode}})
	if status != http.StatusFound {
		t.Fatalf("one membership: %d", status)
	}
	if org := claims(t, f.exchange(flowClient, loc)["access_token"])["org_id"]; org != "org_test" {
		t.Fatalf("org_id %v, want org_test", org)
	}

	// Naming the organization skips the picker.
	f = startFlow(t, ts, flowClient, "&organization=org_test")
	if status, _, loc = f.signIn("+14155551234"); status != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("named organization: %d %s", status, loc)
	}
}

func TestOrganizationRequiredWithoutMembership(t *testing.T) {
	ts := flowServer(t, orgBehaviorPostLogin)
	f := startFlow(t, ts, flowClient, "")
	// The SMS connection creates the new user on sign-in, with no membership.
	status, _, loc := f.signIn("+14155559999")
	if status != http.StatusFound || loc.Query().Get("error") != "invalid_request" ||
		loc.Query().Get("error_description") != errNoOrganizations {
		t.Fatalf("no membership: %d %s", status, loc)
	}

	// no_prompt needs the organization named up front: refused before the
	// login page.
	ts = flowServer(t, "no_prompt")
	if loc := authorizeRedirect(t, ts, flowClient, ""); loc.Query().Get("error_description") != errOrganizationMissing {
		t.Fatalf("no prompt: %s", loc)
	}
}

func TestMultifactorFromAction(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("second-factor", `
		exports.onExecutePostLogin = async (event, api) => {
		  const done = event.authentication.methods.some((x) => x.name === 'mfa');
		  if (!done && event.transaction.protocol !== 'oauth2-refresh-token') {
		    api.multifactor.enable('any', { allowRememberBrowser: false });
		  }
		  api.accessToken.setCustomClaim('https://mock/mfa', done);
		};`)

	f := startFlow(t, ts, "test_client_actions", "")
	status, body, _ := f.signIn("+14155551234")
	if status != http.StatusOK || !strings.Contains(body, "Verify it") || !strings.Contains(body, `autocomplete="one-time-code"`) {
		t.Fatalf("second factor page: %d %s", status, body)
	}
	if status, body, _ = f.post(url.Values{"mfa_code": {"000000"}}); status != http.StatusBadRequest || !strings.Contains(body, "not right") {
		t.Fatalf("wrong code: %d %s", status, body)
	}
	status, _, loc := f.post(url.Values{"mfa_code": {passwordlessCode}})
	if status != http.StatusFound {
		t.Fatalf("right code: %d", status)
	}
	tok := f.exchange("test_client_actions", loc)
	// The Actions ran before the second factor, as in Auth0.
	if v := claims(t, tok["access_token"])["https://mock/mfa"]; v != false {
		t.Fatalf("login claim %v", v)
	}

	// A refresh runs without the browser session: its Actions see no second
	// factor, as Auth0's do.
	resp, err := f.hc.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"test_client_actions"}, "refresh_token": {tok["refresh_token"].(string)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var refreshed map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&refreshed)
	if resp.StatusCode != http.StatusOK || claims(t, refreshed["access_token"])["https://mock/mfa"] != false {
		t.Fatalf("refresh: %d %v", resp.StatusCode, refreshed)
	}
}

func TestMultifactorOnTokenRequestIsRefused(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("always", `
		exports.onExecutePostLogin = async (event, api) => {
		  if (event.transaction.protocol === 'oauth2-refresh-token') api.multifactor.enable('any');
		};`)
	_, tok := loginWithScope(t, ts, "openid offline_access", "")
	resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"test_client_actions"}, "refresh_token": {tok["refresh_token"].(string)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusForbidden || out["error"] != "access_denied" {
		t.Fatalf("refresh asking for a second factor: %d %v", resp.StatusCode, out)
	}
}

// An organization login's event.authorization.roles is the member's role in
// that organization, not the user's tenant roles.
func TestOrganizationLoginRoles(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.mu.Lock()
	srv.roles["rol_t"] = &config.Role{ID: "rol_t", Name: "tenant-wide"}
	srv.userRoles["test_user_1"] = []string{"rol_t"}
	srv.mu.Unlock()
	m := mgmt{t, ts.URL}
	m.deployBound("roles", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/roles", event.authorization.roles.join(","));
		};`)

	st, tok := login(t, ts, "&organization=org_test")
	if st != http.StatusOK {
		t.Fatalf("login: %d %v", st, tok)
	}
	if got := claims(t, tok["access_token"])["https://mock/roles"]; got != "admin" {
		t.Fatalf("organization login roles = %q, want the member role", got)
	}
	st, tok = login(t, ts, "")
	if st != http.StatusOK {
		t.Fatalf("login: %d %v", st, tok)
	}
	if got := claims(t, tok["access_token"])["https://mock/roles"]; got != "tenant-wide" {
		t.Fatalf("login without an organization roles = %q, want tenant roles", got)
	}
}

// The organization prompt offers only organizations the login's connection
// is enabled on.
func TestOrganizationPromptFollowsConnection(t *testing.T) {
	ts := flowServer(t, orgBehaviorPostLogin)
	// Turn off SMS on org_second: an SMS login sees org_test alone and
	// signs straight in to it.
	m := sdk(t, ts)
	if err := m.Organization.DeleteConnection(t.Context(), "org_second", "con_sms"); err != nil {
		t.Fatalf("disable connection: %v", err)
	}
	f := startFlow(t, ts, flowClient, "")
	status, body, loc := f.signIn("+14155551234")
	if status != http.StatusFound {
		t.Fatalf("SMS login: %d %s", status, body)
	}
	if org := claims(t, f.exchange(flowClient, loc)["access_token"])["org_id"]; org != "org_test" {
		t.Fatalf("org_id %v, want org_test", org)
	}
}

// PATCH /api/v2/clients/{id} sets the organization settings, as the SDK's
// Client.Update sends them.
func TestClientPatchOrganizationSettings(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := sdk(t, ts)
	ctx := t.Context()
	err := m.Client.Update(ctx, "mgmt_client_dev", &management.Client{
		OrganizationUsage:           auth0.String("require"),
		OrganizationRequireBehavior: auth0.String("post_login_prompt"),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	c, err := m.Client.Read(ctx, "mgmt_client_dev")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if c.GetOrganizationUsage() != "require" || c.GetOrganizationRequireBehavior() != "post_login_prompt" {
		t.Fatalf("read back %q %q", c.GetOrganizationUsage(), c.GetOrganizationRequireBehavior())
	}
	// An invalid value is refused and changes nothing.
	if err := m.Client.Update(ctx, "mgmt_client_dev", &management.Client{OrganizationUsage: auth0.String("required")}); err == nil {
		t.Fatal("invalid organization_usage accepted")
	}
	if c, _ = m.Client.Read(ctx, "mgmt_client_dev"); c.GetOrganizationUsage() != "require" {
		t.Fatalf("after a refused update: %q", c.GetOrganizationUsage())
	}
}

// sdk is a Management API client on the test server, as consumers use one.
func sdk(t *testing.T, ts *httptest.Server) *management.Management {
	t.Helper()
	m, err := management.New(ts.URL, management.WithClientCredentials(t.Context(), "mgmt_client_dev", "mgmt_secret_dev"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management client: %v", err)
	}
	return m
}

// A code exchanged after a delay carries the exchange's iat and exp; the
// login's auth_time stays.
func TestReissueKeepsLifetime(t *testing.T) {
	// As loginTokenClaims builds them (int64), and as decoded (float64).
	for _, c := range []map[string]any{
		{"iat": int64(1000), "exp": int64(4600), "auth_time": int64(1000)},
		{"iat": float64(1000), "exp": float64(4600), "auth_time": int64(1000)},
	} {
		reissue(c, time.Unix(5000, 0))
		if c["iat"] != int64(5000) || c["exp"] != int64(8600) || c["auth_time"] != int64(1000) {
			t.Fatalf("reissued %v", c)
		}
	}
}

// An organization login to a client that denies organizations is refused.
func TestOrganizationDeniedForClient(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := sdk(t, ts)
	if err := m.Client.Update(t.Context(), "mgmt_client_dev", &management.Client{OrganizationUsage: auth0.String("deny")}); err != nil {
		t.Fatalf("update: %v", err)
	}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Get(ts.URL + "/authorize?response_type=code&client_id=mgmt_client_dev&redirect_uri=" +
		url.QueryEscape("http://localhost:3000/callback") + "&organization=org_test")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("deny: %d %s", resp.StatusCode, loc)
	}
	if err := m.Client.Update(t.Context(), "mgmt_client_dev", &management.Client{
		OrganizationRequireBehavior: auth0.String("pre_login_prompt"),
	}); err == nil {
		t.Fatal("pre_login_prompt accepted")
	}
}

// A code older than authCodeLifetime is refused.
func TestAuthorizationCodeExpires(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	f := startFlow(t, ts, "test_client_actions", "")
	status, _, loc := f.signIn("+14155551234")
	if status != http.StatusFound {
		t.Fatalf("login: %d", status)
	}
	srv.mu.Lock()
	srv.authCodes[loc.Query().Get("code")].IssuedAt = time.Now().Add(-authCodeLifetime - time.Second)
	srv.mu.Unlock()
	resp, err := f.hc.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"test_client_actions"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"http://localhost:3000/callback"}, "code_verifier": {f.verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stale code: %d", resp.StatusCode)
	}
}

// An Action that moves the user's stored tenant during the login does not
// move the login's refresh tokens to another organization.
func TestRefreshKeepsTheLoginsOrganization(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("moves-tenant", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.user.setAppMetadata("tenant_id", "org_elsewhere");
		};`)
	st, tok := loginWithScope(t, ts, "openid offline_access", "")
	if st != http.StatusOK || claims(t, tok["access_token"])["org_id"] != "org_test" {
		t.Fatalf("login: %d %v", st, tok)
	}
	resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"test_client_actions"}, "refresh_token": {tok["refresh_token"].(string)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK || claims(t, out["access_token"])["org_id"] != "org_test" {
		t.Fatalf("refresh: %d %v", resp.StatusCode, out)
	}
}

// Once a login waits on its second factor, its first step cannot be posted
// again to start over.
func TestSecondFactorCannotBeSkippedByReposting(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("second-factor", `
		exports.onExecutePostLogin = async (event, api) => {
		  if (!event.authentication.methods.some((x) => x.name === 'mfa')) api.multifactor.enable('any');
		};`)
	f := startFlow(t, ts, "test_client_actions", "")
	if status, body, _ := f.signIn("+14155551234"); status != http.StatusOK || !strings.Contains(body, `name="mfa_code"`) {
		t.Fatalf("second factor page: %d", status)
	}
	if status, _, loc := f.signIn("+14155551234"); status != http.StatusBadRequest || loc.Query().Get("code") != "" {
		t.Fatalf("reposting the first step: %d %s", status, loc)
	}
	if status, _, loc := f.post(url.Values{"mfa_code": {passwordlessCode}}); status != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("second factor still completes: %d", status)
	}
}

// A login an Action denied is over: its code cannot be posted again.
func TestDeniedLoginCannotBeReposted(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("deny", `exports.onExecutePostLogin = async (event, api) => { api.access.deny("no"); };`)
	f := startFlow(t, ts, "test_client_actions", "")
	if status, _, loc := f.signIn("+14155551234"); status != http.StatusFound || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("denied: %d %s", status, loc)
	}
	if status, _, _ := f.signIn("+14155551234"); status != http.StatusBadRequest {
		t.Fatalf("reposted: %d", status)
	}
}

// A login that named no organization keeps tenant roles in its Actions on
// refresh, though its token's organization came from the stored tenant.
func TestRefreshKeepsTenantRoleContext(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.mu.Lock()
	srv.roles["rol_t"] = &config.Role{ID: "rol_t", Name: "tenant-wide"}
	srv.userRoles["test_user_1"] = []string{"rol_t"}
	srv.mu.Unlock()
	m := mgmt{t, ts.URL}
	m.deployBound("roles", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/roles", event.authorization.roles.join(","));
		};`)
	st, tok := loginWithScope(t, ts, "openid offline_access", "")
	if st != http.StatusOK || claims(t, tok["access_token"])["https://mock/roles"] != "tenant-wide" {
		t.Fatalf("login: %d %v", st, claims(t, tok["access_token"]))
	}
	resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"test_client_actions"}, "refresh_token": {tok["refresh_token"].(string)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if got := claims(t, out["access_token"])["https://mock/roles"]; resp.StatusCode != http.StatusOK || got != "tenant-wide" {
		t.Fatalf("refresh roles %v (%d)", got, resp.StatusCode)
	}
}

// A passwordless code verifies the address before the login's claims and
// Actions are built.
func TestPasswordlessVerificationReachesTheFirstToken(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.mu.Lock()
	srv.users["test_user_2"].EmailVerified = false
	srv.mu.Unlock()
	m := mgmt{t, ts.URL}
	m.deployBound("verified", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.idToken.setCustomClaim("https://mock/verified", event.user.email_verified);
		};`)
	f := startFlow(t, ts, "test_client_actions", "")
	status, _, loc := f.post(url.Values{"email": {"email@example.test"}, "code": {passwordlessCode}})
	if status != http.StatusFound {
		t.Fatalf("login: %d", status)
	}
	id := claims(t, f.exchange("test_client_actions", loc)["id_token"])
	if id["email_verified"] != true || id["https://mock/verified"] != true {
		t.Fatalf("id token: %v", id)
	}
}

// authorizeRedirect sends GET /authorize and returns where it redirects.
func authorizeRedirect(t *testing.T, ts *httptest.Server, client, extra string) *url.URL {
	t.Helper()
	base := *ts.Client()
	hc := &base
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(ts.URL + "/authorize?response_type=code&client_id=" + client + "&redirect_uri=" +
		url.QueryEscape("http://localhost:3000/callback") + extra)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc
}

// api.multifactor.enable('none') turns the second factor off.
func TestMultifactorNoneIsNoPrompt(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("none", `exports.onExecutePostLogin = async (event, api) => { api.multifactor.enable('none'); };`)
	f := startFlow(t, ts, "test_client_actions", "")
	if status, _, loc := f.signIn("+14155551234"); status != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("provider none prompted: %d", status)
	}
}

// A later api.multifactor.enable('none') cancels an earlier request.
func TestMultifactorNoneCancelsAnEarlierRequest(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("both", `exports.onExecutePostLogin = async (event, api) => {
	  api.multifactor.enable('any');
	  api.multifactor.enable('none');
	};`)
	f := startFlow(t, ts, "test_client_actions", "")
	if status, _, loc := f.signIn("+14155551234"); status != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("still prompted: %d", status)
	}
}

// A client that denies organizations gets tokens without one, even for a
// user with a stored tenant, and its Actions see the /authorize request.
func TestDeniedClientGetsNoStoredTenant(t *testing.T) {
	_, ts := setupTestServerWith(t, func(cfg *config.Config) {
		cfg.Clients = append(cfg.Clients, config.Client{
			ClientID: "deny_spa", AppType: "spa", OrganizationUsage: "deny",
			GrantTypes: []string{"authorization_code", "refresh_token"}, Callbacks: []string{"http://localhost:3000/callback"},
		})
	})
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("request", `exports.onExecutePostLogin = async (event, api) => {
	  api.accessToken.setCustomClaim("https://mock/method", event.request.method);
	  api.accessToken.setCustomClaim("https://mock/org", event.organization ? event.organization.id : "");
	};`)
	f := startFlow(t, ts, "deny_spa", "")
	status, _, loc := f.signIn("+14155551234")
	if status != http.StatusFound {
		t.Fatalf("login: %d", status)
	}
	tok := f.exchange("deny_spa", loc)
	a := claims(t, tok["access_token"])
	if a["https://mock/method"] != "GET" {
		t.Fatalf("event.request.method %v, want GET", a["https://mock/method"])
	}
	if a["org_id"] != nil || a["https://mock/org"] != "" {
		t.Fatalf("denied client got an organization: %v", a)
	}
	resp, err := f.hc.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"deny_spa"}, "refresh_token": {tok["refresh_token"].(string)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if r := claims(t, out["access_token"]); resp.StatusCode != http.StatusOK || r["org_id"] != nil || r["https://mock/org"] != "" {
		t.Fatalf("refresh: %d %v", resp.StatusCode, r)
	}
}

// A device client that denies organizations refuses one named up front.
func TestDeviceFlowHonoursDeny(t *testing.T) {
	_, ts := setupTestServerWith(t, func(cfg *config.Config) {
		cfg.Clients = append(cfg.Clients, config.Client{
			ClientID: "deny_device", AppType: "native", OrganizationUsage: "deny",
			GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		})
	})
	defer ts.Close()
	resp, err := http.PostForm(ts.URL+"/oauth/device/code", url.Values{
		"client_id": {"deny_device"}, "scope": {"openid"}, "organization": {"org_test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("device authorization with an organization: %d", resp.StatusCode)
	}
}

// An unsupported second-factor provider fails the login.
func TestMultifactorUnsupportedProviderFails(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("typo", `exports.onExecutePostLogin = async (event, api) => { api.multifactor.enable('gaurdian'); };`)
	f := startFlow(t, ts, "test_client_actions", "")
	if status, _, loc := f.signIn("+14155551234"); status != http.StatusFound || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("typo provider: %d %s", status, loc)
	}
}

// A login that settled on no organization keeps none on refresh, though
// the user later gains a stored tenant.
func TestRefreshKeepsASettledEmptyOrganization(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("org", `exports.onExecutePostLogin = async (event, api) => {
	  api.accessToken.setCustomClaim("https://mock/org", event.organization ? event.organization.id : "");
	};`)
	srv.mu.Lock()
	delete(srv.users["test_user_1"].AppMetadata, config.AppMetaTenantID)
	srv.mu.Unlock()
	f := startFlow(t, ts, "test_client_actions", "")
	_, _, loc := f.signIn("+14155551234")
	tok := f.exchange("test_client_actions", loc)
	if claims(t, tok["access_token"])["org_id"] != nil {
		t.Fatalf("login org: %v", claims(t, tok["access_token"]))
	}
	srv.mu.Lock()
	srv.users["test_user_1"].AppMetadata[config.AppMetaTenantID] = "org_test"
	srv.mu.Unlock()
	resp, err := f.hc.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"test_client_actions"}, "refresh_token": {tok["refresh_token"].(string)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if c := claims(t, out["access_token"]); resp.StatusCode != http.StatusOK || c["org_id"] != nil || c["https://mock/org"] != "" {
		t.Fatalf("refresh: %d %v", resp.StatusCode, c)
	}
}

// A device client that requires an organization must name one.
func TestDeviceFlowNeedsTheRequiredOrganization(t *testing.T) {
	_, ts := setupTestServerWith(t, func(cfg *config.Config) {
		cfg.Clients = append(cfg.Clients, config.Client{
			ClientID: "require_device", AppType: "native", OrganizationUsage: orgUsageRequire, OrganizationRequireBehavior: orgBehaviorPostLogin,
			GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		})
	})
	defer ts.Close()
	for org, want := range map[string]int{"": http.StatusBadRequest, "org_test": http.StatusOK} {
		form := url.Values{"client_id": {"require_device"}, "scope": {"openid"}}
		if org != "" {
			form.Set("organization", org)
		}
		resp, err := http.PostForm(ts.URL+"/oauth/device/code", form)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("organization %q: %d, want %d", org, resp.StatusCode, want)
		}
	}
}

// A finished login leaves no second-factor record behind.
func TestSecondFactorRecordCleared(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("mfa", `exports.onExecutePostLogin = async (event, api) => { api.multifactor.enable('any'); };`)
	f := startFlow(t, ts, "test_client_actions", "")
	f.signIn("+14155551234")
	if status, _, _ := f.post(url.Values{"mfa_code": {passwordlessCode}}); status != http.StatusFound {
		t.Fatalf("second factor: %d", status)
	}
	srv.mu.RLock()
	n := len(srv.mfaSessions)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("%d second-factor records left", n)
	}
}

// Without connections in the config, the prompt offers every membership.
func TestOrganizationPromptWithoutConnections(t *testing.T) {
	_, ts := setupTestServerWith(t, func(cfg *config.Config) {
		cfg.Connections = nil
		cfg.Clients = append(cfg.Clients, config.Client{
			ClientID: flowClient, AppType: "spa", GrantTypes: []string{"authorization_code"},
			Callbacks: []string{"http://localhost:3000/callback"}, OrganizationUsage: orgUsageRequire, OrganizationRequireBehavior: orgBehaviorPostLogin,
		})
	})
	defer ts.Close()
	f := startFlow(t, ts, flowClient, "")
	status, body, loc := f.signIn("+14155551234")
	if status != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("login without connections: %d %s %s", status, loc, body)
	}
	if org := claims(t, f.exchange(flowClient, loc)["access_token"])["org_id"]; org != "org_test" {
		t.Fatalf("org_id %v", org)
	}
}
