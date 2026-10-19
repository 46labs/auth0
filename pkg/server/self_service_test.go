package server

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"

	"github.com/46labs/auth0/pkg/config"
)

func ssoMgmt(t *testing.T) (*Server, *management.Management, string) {
	t.Helper()
	srv, ts := setupTestServer(t)
	t.Cleanup(ts.Close)
	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	return srv, m, ts.URL
}

func createProfile(t *testing.T, m *management.Management) *management.SelfServiceProfile {
	t.Helper()
	p := &management.SelfServiceProfile{
		Name:              auth0.String("pee-sso"),
		Description:       auth0.String("setup"),
		AllowedStrategies: &[]string{"oidc", "samlp", "okta"},
	}
	if err := m.SelfServiceProfile.Create(context.Background(), p); err != nil {
		t.Fatalf("Create profile: %v", err)
	}
	return p
}

func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	var mErr management.Error
	if !errors.As(err, &mErr) || mErr.Status() != status {
		t.Fatalf("err = %v, want status %d", err, status)
	}
}

func TestSelfServiceProfileLifecycle(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()

	p := createProfile(t, m)
	if !strings.HasPrefix(p.GetID(), "ssp_") || p.CreatedAt == nil {
		t.Fatalf("created = %+v", p)
	}

	list, err := m.SelfServiceProfile.List(ctx)
	if err != nil || len(list.SelfServiceProfile) != 1 || list.SelfServiceProfile[0].GetName() != "pee-sso" || list.Length != 0 || list.Total != 1 {
		t.Fatalf("list = %+v, err %v", list, err)
	}

	if err := m.SelfServiceProfile.Update(ctx, p.GetID(), &management.SelfServiceProfile{Description: auth0.String("changed")}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := m.SelfServiceProfile.Read(ctx, p.GetID())
	if err != nil || got.GetDescription() != "changed" || got.GetName() != "pee-sso" {
		t.Fatalf("read = %+v, err %v", got, err)
	}

	if err := m.SelfServiceProfile.Delete(ctx, p.GetID()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = m.SelfServiceProfile.Read(ctx, p.GetID())
	wantStatus(t, err, http.StatusNotFound)
	// A repeated delete answers 204, as recorded.
	if err := m.SelfServiceProfile.Delete(ctx, p.GetID()); err != nil {
		t.Fatalf("repeat Delete: %v", err)
	}
}

func TestSelfServiceProfileRefusesWhatAuth0Refuses(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()

	wantStatus(t, m.SelfServiceProfile.Create(ctx, &management.SelfServiceProfile{Description: auth0.String("x")}), http.StatusBadRequest)
	wantStatus(t, m.SelfServiceProfile.Create(ctx, &management.SelfServiceProfile{
		Name: auth0.String("x"), AllowedStrategies: &[]string{"email"},
	}), http.StatusBadRequest)
	wantStatus(t, m.SelfServiceProfile.Update(ctx, "ssp_missing", &management.SelfServiceProfile{Name: auth0.String("x")}), http.StatusNotFound)
}

// ticket is the request PEE sends for a new connection.
func newConnectionTicket() *management.SelfServiceProfileTicket {
	return &management.SelfServiceProfileTicket{
		EnabledClients: &[]string{"mgmt_client_dev"},
		EnabledOrganizations: []*management.SelfServiceProfileTicketEnabledOrganizations{{
			OrganizationID:          auth0.String("org_test"),
			AssignMembershipOnLogin: auth0.Bool(true),
			ShowAsButton:            auth0.Bool(true),
		}},
		DomainAliasesConfig: &management.SelfServiceProfileTicketDomainAliasesConfig{DomainVerification: auth0.String("required")},
		ConnectionConfig: &management.SelfServiceProfileTicketConnectionConfig{
			Name:               auth0.String("pee-org-test-sso-1234"),
			DisplayName:        auth0.String("Test Organization"),
			IsDomainConnection: auth0.Bool(true),
		},
	}
}

// The setup page is a browser flow the SDK does not cover, so it is driven
// with raw HTTP.
func completeFlow(t *testing.T, ticketURL string, form url.Values) (int, string) {
	t.Helper()
	resp, err := http.PostForm(ticketURL, form)
	if err != nil {
		t.Fatalf("POST flow: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestSSOTicketCreatesTheConnectionWhenTheSetupFinishes(t *testing.T) {
	srv, m, base := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	tk := newConnectionTicket()
	if err := m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if !strings.HasPrefix(tk.GetTicket(), base+"/self-service/connections-flow?ticket=") {
		t.Fatalf("ticket = %q", tk.GetTicket())
	}

	// Nothing exists until the setup finishes.
	if _, err := m.Organization.Connections(ctx, "org_test"); err != nil {
		t.Fatal(err)
	}
	page, err := http.Get(tk.GetTicket())
	if err != nil || page.StatusCode != http.StatusOK {
		t.Fatalf("GET flow: %v %v", page, err)
	}
	_ = page.Body.Close()

	status, body := completeFlow(t, tk.GetTicket(), url.Values{
		"strategy": {"okta"}, "display_name": {""}, "domain_aliases": {"Acme.com, acme.com,example.org"},
	})
	if status != http.StatusOK || !strings.Contains(body, "is set up") {
		t.Fatalf("complete: %d %s", status, body)
	}

	list, err := m.Connection.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var conn *management.Connection
	for _, c := range list.Connections {
		if c.GetName() == "pee-org-test-sso-1234" {
			conn = c
		}
	}
	if conn == nil {
		t.Fatalf("connection not created: %+v", list.Connections)
	}
	if conn.GetStrategy() != "okta" || conn.GetDisplayName() != "Test Organization" || !conn.GetIsDomainConnection() {
		t.Fatalf("connection = %+v", conn)
	}
	opts, ok := conn.Options.(*management.ConnectionOptionsOkta)
	if !ok || strings.Join(opts.GetDomainAliases(), ",") != "acme.com,example.org" {
		t.Fatalf("options = %#v", conn.Options)
	}

	clients, err := m.Connection.ReadEnabledClients(ctx, conn.GetID())
	if err != nil || clients.Clients == nil || len(*clients.Clients) != 1 || (*clients.Clients)[0].GetClientID() != "mgmt_client_dev" {
		t.Fatalf("enabled clients = %+v, err %v", clients, err)
	}
	oc, err := m.Organization.Connection(ctx, "org_test", conn.GetID())
	if err != nil || !oc.GetAssignMembershipOnLogin() || !oc.GetShowAsButton() {
		t.Fatalf("org connection = %+v, err %v", oc, err)
	}

	// A ticket is spent once used.
	if status, _ := completeFlow(t, tk.GetTicket(), url.Values{"strategy": {"okta"}}); status != http.StatusBadRequest {
		t.Fatalf("reuse status = %d", status)
	}
	srv.mu.RLock()
	n := len(srv.connections)
	srv.mu.RUnlock()
	if n != 3 {
		t.Fatalf("connections = %d, want the two seeded and one created", n)
	}
}

func TestSSOTicketEditsAnExistingConnection(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	conn := ssoConnection(t, m)
	tk := newConnectionTicket()
	tk.ConnectionConfig = nil
	tk.ConnectionID = conn.ID
	if err := m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk); err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	// The strategy of an edited connection is fixed; a posted one is ignored.
	if status, body := completeFlow(t, tk.GetTicket(), url.Values{
		"strategy": {"samlp"}, "display_name": {"Acme"}, "domain_aliases": {"acme.com"},
	}); status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, body)
	}
	got, err := m.Connection.Read(ctx, conn.GetID())
	if err != nil || got.GetStrategy() != "oidc" || got.GetDisplayName() != "Acme" {
		t.Fatalf("connection = %+v, err %v", got, err)
	}
	if _, err := m.Organization.Connection(ctx, "org_test", conn.GetID()); err != nil {
		t.Fatalf("not enabled on the organization: %v", err)
	}
}

func TestSSOTicketRefusesWhatCannotComplete(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	email := "con_email"
	cases := map[string]struct {
		mutate func(*management.SelfServiceProfileTicket)
		status int
	}{
		"both connection forms":   {func(tk *management.SelfServiceProfileTicket) { tk.ConnectionID = auth0.String("con_sms") }, 400},
		"neither connection form": {func(tk *management.SelfServiceProfileTicket) { tk.ConnectionConfig = nil }, 400},
		"unnamed connection":      {func(tk *management.SelfServiceProfileTicket) { tk.ConnectionConfig.Name = nil }, 400},
		"unknown connection": {func(tk *management.SelfServiceProfileTicket) {
			tk.ConnectionConfig, tk.ConnectionID = nil, auth0.String("con_missing")
		}, 404},
		"strategy not in profile": {func(tk *management.SelfServiceProfileTicket) {
			tk.ConnectionConfig, tk.ConnectionID = nil, &email
		}, 400},
		"unknown client": {func(tk *management.SelfServiceProfileTicket) { tk.EnabledClients = &[]string{"nope"} }, 400},
		"unknown organization": {func(tk *management.SelfServiceProfileTicket) {
			tk.EnabledOrganizations[0].OrganizationID = auth0.String("org_missing")
		}, 400},
		"bad verification mode": {func(tk *management.SelfServiceProfileTicket) {
			tk.DomainAliasesConfig.DomainVerification = auth0.String("sometimes")
		}, 400},
		"field the mock drops": {func(tk *management.SelfServiceProfileTicket) {
			tk.ConnectionConfig.ShowAsButton = auth0.Bool(true)
		}, 400},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tk := newConnectionTicket()
			tc.mutate(tk)
			wantStatus(t, m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk), tc.status)
		})
	}
	wantStatus(t, m.SelfServiceProfile.CreateTicket(ctx, "ssp_missing", newConnectionTicket()), http.StatusNotFound)
}

func TestSSOTicketFlowRefusesRevokedAndDisallowedStrategies(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	tk := newConnectionTicket()
	if err := m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk); err != nil {
		t.Fatal(err)
	}
	if status, _ := completeFlow(t, tk.GetTicket(), url.Values{"strategy": {"waad"}}); status != http.StatusBadRequest {
		t.Fatalf("disallowed strategy status = %d", status)
	}

	u, _ := url.Parse(tk.GetTicket())
	if err := m.SelfServiceProfile.RevokeTicket(ctx, p.GetID(), u.Query().Get("ticket")); err != nil {
		t.Fatalf("RevokeTicket: %v", err)
	}
	if status, _ := completeFlow(t, tk.GetTicket(), url.Values{"strategy": {"oidc"}}); status != http.StatusBadRequest {
		t.Fatalf("revoked status = %d", status)
	}
}

// Two setups finishing at once for the same derived name create one
// connection, not two.
func TestSSOTicketFlowCompletesOnceUnderConcurrency(t *testing.T) {
	srv, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	var tickets []string
	for range 8 {
		tk := newConnectionTicket()
		if err := m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk); err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, tk.GetTicket())
	}
	var wg sync.WaitGroup
	statuses := make([]int, len(tickets))
	for i, tu := range tickets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.PostForm(tu, url.Values{"strategy": {"oidc"}})
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			statuses[i] = resp.StatusCode
		}()
	}
	wg.Wait()

	ok := 0
	for _, s := range statuses {
		if s == http.StatusOK {
			ok++
		}
	}
	srv.mu.RLock()
	n := len(srv.connections)
	srv.mu.RUnlock()
	if ok != 1 || n != 3 {
		t.Fatalf("succeeded %d, connections %d; want one of each", ok, n)
	}
}

func TestSelfServiceProfileUpdateRefusesAnInvalidResult(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	wantStatus(t, m.SelfServiceProfile.Update(ctx, p.GetID(), &management.SelfServiceProfile{Name: auth0.String("")}), http.StatusBadRequest)

	withAttrs := []*management.SelfServiceProfileUserAttributes{{
		Name: auth0.String("email"), Description: auth0.String("Email"), IsOptional: auth0.Bool(false),
	}}
	if err := m.SelfServiceProfile.Update(ctx, p.GetID(), &management.SelfServiceProfile{UserAttributes: withAttrs}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, m.SelfServiceProfile.Update(ctx, p.GetID(), &management.SelfServiceProfile{UserAttributeProfileID: auth0.String("uap_1")}), http.StatusBadRequest)

	got, err := m.SelfServiceProfile.Read(ctx, p.GetID())
	if err != nil || got.GetName() != "pee-sso" || got.GetUserAttributeProfileID() != "" {
		t.Fatalf("refused update changed the profile: %+v, err %v", got, err)
	}
}

// What a ticket names can go away during its lifetime; finishing it then must
// fail without writing anything.
func TestSSOTicketFlowRevalidatesBeforeWriting(t *testing.T) {
	srv, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	tk := newConnectionTicket()
	if err := m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk); err != nil {
		t.Fatal(err)
	}
	if err := m.Organization.Delete(ctx, "org_test"); err != nil {
		t.Fatal(err)
	}
	if status, _ := completeFlow(t, tk.GetTicket(), url.Values{"strategy": {"oidc"}}); status != http.StatusBadRequest {
		t.Fatalf("status = %d", status)
	}
	srv.mu.RLock()
	n, pairings := len(srv.connections), len(srv.orgConnections["org_test"])
	srv.mu.RUnlock()
	if n != 2 || pairings != 0 {
		t.Fatalf("wrote on refusal: %d connections, %d pairings", n, pairings)
	}
}

// A pairing with signup on cannot lose auto-membership, the same rule the
// enabled_connections PATCH enforces.
func TestSSOTicketFlowRefusesAnInvalidPairing(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	conn := ssoConnection(t, m)
	if err := m.Organization.AddConnection(ctx, "org_test", &management.OrganizationConnection{
		ConnectionID: conn.ID, AssignMembershipOnLogin: auth0.Bool(true), IsSignupEnabled: auth0.Bool(true),
	}); err != nil {
		t.Fatal(err)
	}
	tk := newConnectionTicket()
	tk.ConnectionConfig, tk.ConnectionID = nil, conn.ID
	tk.EnabledOrganizations[0].AssignMembershipOnLogin = auth0.Bool(false)
	if err := m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk); err != nil {
		t.Fatal(err)
	}
	if status, _ := completeFlow(t, tk.GetTicket(), url.Values{"display_name": {"Changed"}}); status != http.StatusBadRequest {
		t.Fatalf("status = %d", status)
	}
	got, err := m.Connection.Read(ctx, conn.GetID())
	if err != nil || got.GetDisplayName() == "Changed" {
		t.Fatalf("wrote on refusal: %+v, err %v", got, err)
	}
}

func TestSelfServiceProfileRefusesInvalidNestedFields(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()

	wantStatus(t, m.SelfServiceProfile.Create(ctx, &management.SelfServiceProfile{
		Name: auth0.String("x"), Branding: &management.Branding{LogoURL: auth0.String("http://example.com/logo.png")},
	}), http.StatusBadRequest)
	// Keys the typed SDK structs cannot send go through the exported Request.
	for name, body := range map[string]map[string]any{
		"unknown branding key":  {"name": "x", "branding": map[string]any{"favicon": "https://example.com/f.png"}},
		"unknown attribute key": {"name": "x", "user_attributes": []any{map[string]any{"name": "email", "required": true}}},
	} {
		t.Run(name, func(t *testing.T) {
			wantStatus(t, m.Request(ctx, http.MethodPost, m.URI("self-service-profiles"), body), http.StatusBadRequest)
		})
	}

	p := &management.SelfServiceProfile{
		Name:     auth0.String("branded"),
		Branding: &management.Branding{LogoURL: auth0.String("https://example.com/logo.png"), Colors: &management.BrandingColors{Primary: auth0.String("#334455")}},
	}
	if err := m.SelfServiceProfile.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := m.SelfServiceProfile.Read(ctx, p.GetID())
	if err != nil || got.Branding.GetLogoURL() != "https://example.com/logo.png" || got.Branding.Colors.GetPrimary() != "#334455" {
		t.Fatalf("read = %+v, err %v", got, err)
	}
}

func TestSSOTicketRefusesAnOverflowingTTL(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	p := createProfile(t, m)
	tk := newConnectionTicket()
	tk.TTLSec = math.MaxInt64
	wantStatus(t, m.SelfServiceProfile.CreateTicket(context.Background(), p.GetID(), tk), http.StatusBadRequest)
}

// Spent, revoked and expired tickets leave the store.
func TestSSOTicketStoreDropsFinishedTickets(t *testing.T) {
	srv, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)

	issue := func() string {
		tk := newConnectionTicket()
		if err := m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk); err != nil {
			t.Fatal(err)
		}
		return tk.GetTicket()
	}
	used := issue()
	if status, _ := completeFlow(t, used, url.Values{"strategy": {"oidc"}}); status != http.StatusOK {
		t.Fatalf("complete status = %d", status)
	}
	revoked, _ := url.Parse(issue())
	if err := m.SelfServiceProfile.RevokeTicket(ctx, p.GetID(), revoked.Query().Get("ticket")); err != nil {
		t.Fatal(err)
	}
	expired, _ := url.Parse(issue())
	srv.mu.Lock()
	srv.ssoTickets[expired.Query().Get("ticket")].ExpiresAt = time.Now().Add(-time.Minute)
	srv.mu.Unlock()

	live := issue()
	srv.mu.RLock()
	n := len(srv.ssoTickets)
	srv.mu.RUnlock()
	if n != 1 {
		t.Fatalf("tickets stored = %d, want only %s", n, live)
	}
}

// Sent together, the two attribute sources are refused even when the id is
// empty, as the SDK refuses them.
func TestSelfServiceProfileRefusesBothAttributeSources(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	body := map[string]any{
		"name":                      "x",
		"user_attributes":           []any{map[string]any{"name": "email", "description": "Email", "is_optional": false}},
		"user_attribute_profile_id": "",
	}
	wantStatus(t, m.Request(context.Background(), http.MethodPost, m.URI("self-service-profiles"), body), http.StatusBadRequest)
}

// A connection configured in Go holds domain_aliases as []string; editing it
// through a ticket keeps them.
func TestSSOTicketEditKeepsConfiguredStringAliases(t *testing.T) {
	srv, m, _ := ssoMgmt(t)
	ctx := context.Background()
	p := createProfile(t, m)
	srv.mu.Lock()
	srv.connections["con_cfg"] = &config.Connection{ID: "con_cfg", Name: "cfg-oidc", Strategy: "oidc", Options: map[string]any{"domain_aliases": []string{"acme.com"}}}
	srv.mu.Unlock()

	tk := newConnectionTicket()
	tk.ConnectionConfig, tk.ConnectionID = nil, auth0.String("con_cfg")
	if err := m.SelfServiceProfile.CreateTicket(ctx, p.GetID(), tk); err != nil {
		t.Fatal(err)
	}
	page, err := http.Get(tk.GetTicket())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if !strings.Contains(string(body), `value="acme.com"`) {
		t.Fatalf("setup page does not show the configured domains: %s", body)
	}
}
