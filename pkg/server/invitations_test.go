package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/auth0/go-auth0/management"
)

// inviteFixture prepares an organization that can actually be invited to: a
// non-passwordless connection enabled on it, and a client with an
// initiate_login_uri. The seeded config deliberately has neither, which is the
// situation the design calls out.
type inviteFixture struct {
	m            *management.Management
	srv          *Server
	ts           *httptest.Server
	orgID        string
	clientID     string
	loginURI     string
	connectionID string
	adminRoleID  string
}

func newInviteFixture(t *testing.T) (*inviteFixture, func()) {
	t.Helper()

	srv, ts := setupTestServer(t)
	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		ts.Close()
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	name := "enterprise-sso"
	strategy := "oidc"
	conn := &management.Connection{Name: &name, Strategy: &strategy}
	if err := m.Connection.Create(ctx, conn); err != nil {
		ts.Close()
		t.Fatalf("Connection.Create: %v", err)
	}
	if err := m.Organization.AddConnection(ctx, "org_test",
		&management.OrganizationConnection{ConnectionID: conn.ID}); err != nil {
		ts.Close()
		t.Fatalf("Organization.AddConnection: %v", err)
	}

	// pee provisions its admin carrier role at runtime by name; invitations
	// then carry the resolved id.
	adminRole := &management.Role{Name: auth0String("admin")}
	if err := m.Role.Create(ctx, adminRole); err != nil {
		ts.Close()
		t.Fatalf("Role.Create: %v", err)
	}

	clientName := "Invite SPA"
	appType := "spa"
	loginURI := "https://app.example.test/login"
	c := &management.Client{Name: &clientName, AppType: &appType, InitiateLoginURI: &loginURI}
	if err := m.Client.Create(ctx, c); err != nil {
		ts.Close()
		t.Fatalf("Client.Create: %v", err)
	}

	return &inviteFixture{
		m:            m,
		srv:          srv,
		ts:           ts,
		orgID:        "org_test",
		clientID:     c.GetClientID(),
		loginURI:     loginURI,
		connectionID: conn.GetID(),
		adminRoleID:  adminRole.GetID(),
	}, ts.Close
}

func (f *inviteFixture) invitation(email string) *management.OrganizationInvitation {
	inviter := "Platform Admin"
	return &management.OrganizationInvitation{
		Inviter:  &management.OrganizationInvitationInviter{Name: &inviter},
		Invitee:  &management.OrganizationInvitationInvitee{Email: &email},
		ClientID: &f.clientID,
		Roles:    []string{f.adminRoleID},
	}
}

// auth0String is the pointer-taking the SDK's optional fields require.
func auth0String(s string) *string { return &s }

// TestSDKCreateInvitation is the core of the design: a platform admin invites
// an email address and gets back a URL that carries the ticket and the
// organization.
func TestSDKCreateInvitation(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inv := f.invitation("invitee@example.test")
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	if inv.GetID() == "" {
		t.Error("no invitation id returned")
	}
	if inv.GetOrganizationID() != f.orgID {
		t.Errorf("organization_id = %q, want %q", inv.GetOrganizationID(), f.orgID)
	}
	if inv.GetTicketID() == "" {
		t.Error("no ticket_id returned")
	}
	if inv.GetInvitee().GetEmail() != "invitee@example.test" {
		t.Errorf("invitee.email = %q", inv.GetInvitee().GetEmail())
	}
	if inv.GetInviter().GetName() != "Platform Admin" {
		t.Errorf("inviter.name = %q", inv.GetInviter().GetName())
	}
	// roles are role ids on the wire; the name appears on acceptance.
	if len(inv.Roles) != 1 || inv.Roles[0] != f.adminRoleID {
		t.Errorf("roles = %+v, want [%s]", inv.Roles, f.adminRoleID)
	}

	// The URL is what the SPA forwards to loginWithRedirect, so its query
	// parameters are load-bearing.
	u, err := url.Parse(inv.GetInvitationURL())
	if err != nil {
		t.Fatalf("invitation_url not parseable: %v", err)
	}
	if got := u.Query().Get("invitation"); got != inv.GetTicketID() {
		t.Errorf("invitation param = %q, want ticket %q", got, inv.GetTicketID())
	}
	if got := u.Query().Get("organization"); got != f.orgID {
		t.Errorf("organization param = %q, want %q", got, f.orgID)
	}
	if got := u.Query().Get("organization_name"); got != "test-org" {
		t.Errorf("organization_name param = %q, want test-org", got)
	}
	if u.Scheme+"://"+u.Host+u.Path != f.loginURI {
		t.Errorf("invitation_url not rooted at initiate_login_uri: %q", inv.GetInvitationURL())
	}

	// Default TTL is 7 days.
	created, err := time.Parse(auth0TimeFormat, inv.GetCreatedAt())
	if err != nil {
		t.Fatalf("created_at not ISO 8601: %q (%v)", inv.GetCreatedAt(), err)
	}
	expires, err := time.Parse(auth0TimeFormat, inv.GetExpiresAt())
	if err != nil {
		t.Fatalf("expires_at not ISO 8601: %q (%v)", inv.GetExpiresAt(), err)
	}
	if got := expires.Sub(created); got != config.InvitationDefaultTTLSec*time.Second {
		t.Errorf("default TTL = %v, want %d seconds", got, config.InvitationDefaultTTLSec)
	}
}

// TestSDKListInvitations covers the requirement the design calls out
// explicitly: the list route used to fall through to org-read and answer 200
// with the organization, which reads as success.
func TestSDKListInvitations(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	empty, err := f.m.Organization.Invitations(ctx, f.orgID)
	if err != nil {
		t.Fatalf("Invitations on empty org: %v", err)
	}
	if len(empty.OrganizationInvitations) != 0 {
		t.Errorf("expected no invitations, got %d", len(empty.OrganizationInvitations))
	}

	for _, email := range []string{"one@example.test", "two@example.test"} {
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, f.invitation(email)); err != nil {
			t.Fatalf("CreateInvitation(%s): %v", email, err)
		}
	}

	list, err := f.m.Organization.Invitations(ctx, f.orgID)
	if err != nil {
		t.Fatalf("Invitations: %v", err)
	}
	if len(list.OrganizationInvitations) != 2 {
		t.Fatalf("expected 2 invitations, got %d", len(list.OrganizationInvitations))
	}

	// Each entry must be an invitation, not the organization wearing an id.
	seen := map[string]bool{}
	for _, inv := range list.OrganizationInvitations {
		if inv.GetInvitee().GetEmail() == "" {
			t.Errorf("list entry has no invitee.email: %+v", inv)
		}
		if inv.GetID() == f.orgID {
			t.Error("list returned the organization as an invitation")
		}
		seen[inv.GetInvitee().GetEmail()] = true
	}
	if !seen["one@example.test"] || !seen["two@example.test"] {
		t.Errorf("both invitees should be listed, got %+v", seen)
	}
}

func TestSDKReadAndRevokeInvitation(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inv := f.invitation("revoke-me@example.test")
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	read, err := f.m.Organization.Invitation(ctx, f.orgID, inv.GetID())
	if err != nil {
		t.Fatalf("Invitation: %v", err)
	}
	if read.GetID() != inv.GetID() {
		t.Errorf("read id = %q, want %q", read.GetID(), inv.GetID())
	}
	if read.GetInvitee().GetEmail() != "revoke-me@example.test" {
		t.Errorf("read invitee = %q", read.GetInvitee().GetEmail())
	}

	if err := f.m.Organization.DeleteInvitation(ctx, f.orgID, inv.GetID()); err != nil {
		t.Fatalf("DeleteInvitation: %v", err)
	}

	_, err = f.m.Organization.Invitation(ctx, f.orgID, inv.GetID())
	assertStatus(t, err, http.StatusNotFound)

	list, err := f.m.Organization.Invitations(ctx, f.orgID)
	if err != nil {
		t.Fatalf("Invitations after revoke: %v", err)
	}
	if len(list.OrganizationInvitations) != 0 {
		t.Errorf("revoked invitation still pending: %+v", list.OrganizationInvitations)
	}

	// Revoking must not touch the organization.
	if _, err := f.m.Organization.Read(ctx, f.orgID); err != nil {
		t.Fatalf("organization destroyed by invitation revoke: %v", err)
	}
}

func TestSDKInvitationValidation(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inviter := "Platform Admin"
	email := "x@example.test"

	t.Run("UnknownOrganization", func(t *testing.T) {
		err := f.m.Organization.CreateInvitation(ctx, "org_missing", f.invitation(email))
		assertStatus(t, err, http.StatusNotFound)
	})

	t.Run("MissingInviter", func(t *testing.T) {
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, &management.OrganizationInvitation{
			Invitee:  &management.OrganizationInvitationInvitee{Email: &email},
			ClientID: &f.clientID,
		})
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("MissingInvitee", func(t *testing.T) {
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, &management.OrganizationInvitation{
			Inviter:  &management.OrganizationInvitationInviter{Name: &inviter},
			ClientID: &f.clientID,
		})
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("MissingClientID", func(t *testing.T) {
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, &management.OrganizationInvitation{
			Inviter: &management.OrganizationInvitationInviter{Name: &inviter},
			Invitee: &management.OrganizationInvitationInvitee{Email: &email},
		})
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("UnknownClient", func(t *testing.T) {
		unknown := "no_such_client"
		inv := f.invitation(email)
		inv.ClientID = &unknown
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("ClientWithoutInitiateLoginURI", func(t *testing.T) {
		name := "No Login URI"
		appType := "spa"
		c := &management.Client{Name: &name, AppType: &appType}
		if err := f.m.Client.Create(ctx, c); err != nil {
			t.Fatalf("Client.Create: %v", err)
		}
		inv := f.invitation(email)
		inv.ClientID = c.ClientID
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("TTLAboveMaximum", func(t *testing.T) {
		tooLong := config.InvitationMaxTTLSec + 1
		inv := f.invitation(email)
		inv.TTLSec = &tooLong
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("TTLNegative", func(t *testing.T) {
		negative := -1
		inv := f.invitation(email)
		inv.TTLSec = &negative
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("TTLZeroUsesDefault", func(t *testing.T) {
		zero := 0
		inv := f.invitation("ttl-zero@example.test")
		inv.TTLSec = &zero
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		created, _ := time.Parse(auth0TimeFormat, inv.GetCreatedAt())
		expires, _ := time.Parse(auth0TimeFormat, inv.GetExpiresAt())
		if got := expires.Sub(created); got != config.InvitationDefaultTTLSec*time.Second {
			t.Errorf("ttl_sec=0 gave %v, want the %d second default", got, config.InvitationDefaultTTLSec)
		}
	})

	t.Run("TTLAtMaximumAccepted", func(t *testing.T) {
		max := config.InvitationMaxTTLSec
		inv := f.invitation("ttl-max@example.test")
		inv.TTLSec = &max
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
			t.Fatalf("ttl_sec at the maximum should be accepted: %v", err)
		}
	})

	t.Run("NamedPasswordlessConnectionRejected", func(t *testing.T) {
		passwordless := "con_email"
		inv := f.invitation(email)
		inv.ConnectionID = &passwordless
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("NamedUnknownConnectionRejected", func(t *testing.T) {
		unknown := "con_nope"
		inv := f.invitation(email)
		inv.ConnectionID = &unknown
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("NamedNonPasswordlessConnectionAccepted", func(t *testing.T) {
		inv := f.invitation("named-conn@example.test")
		inv.ConnectionID = &f.connectionID
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
			t.Fatalf("CreateInvitation with a non-passwordless connection: %v", err)
		}
		if inv.GetConnectionID() != f.connectionID {
			t.Errorf("connection_id = %q, want %q", inv.GetConnectionID(), f.connectionID)
		}
	})
}

// TestInvitationRequiresNonPasswordlessConnection is the seeded-config case:
// only email and SMS exist, both passwordless, so no valid invite can be
// modelled until an enterprise connection is enabled.
func TestInvitationRequiresNonPasswordlessConnection(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	name := "Bare SPA"
	appType := "spa"
	loginURI := "https://app.example.test/login"
	c := &management.Client{Name: &name, AppType: &appType, InitiateLoginURI: &loginURI}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Client.Create: %v", err)
	}

	inviter := "Platform Admin"
	email := "nope@example.test"
	err = m.Organization.CreateInvitation(ctx, "org_test", &management.OrganizationInvitation{
		Inviter:  &management.OrganizationInvitationInviter{Name: &inviter},
		Invitee:  &management.OrganizationInvitationInvitee{Email: &email},
		ClientID: c.ClientID,
	})
	assertStatus(t, err, http.StatusBadRequest)

	// Enabling one makes the same request valid.
	connName := "corp-oidc"
	strategy := "oidc"
	conn := &management.Connection{Name: &connName, Strategy: &strategy}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Connection.Create: %v", err)
	}
	if err := m.Organization.AddConnection(ctx, "org_test",
		&management.OrganizationConnection{ConnectionID: conn.ID}); err != nil {
		t.Fatalf("Organization.AddConnection: %v", err)
	}

	if err := m.Organization.CreateInvitation(ctx, "org_test", &management.OrganizationInvitation{
		Inviter:  &management.OrganizationInvitationInviter{Name: &inviter},
		Invitee:  &management.OrganizationInvitationInvitee{Email: &email},
		ClientID: c.ClientID,
	}); err != nil {
		t.Fatalf("CreateInvitation after enabling a non-passwordless connection: %v", err)
	}
}

// TestInvitationExpiryLapses covers the design's "an expired one lapses on its
// TTL": Auth0 drops it from the pending list rather than reporting it.
func TestInvitationExpiryLapses(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inv := f.invitation("expiring@example.test")
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	// Backdate the expiry rather than sleeping.
	f.srv.mu.Lock()
	stored := f.srv.invitations[f.orgID]
	for i := range stored {
		if stored[i].ID == inv.GetID() {
			stored[i].ExpiresAt = time.Now().Add(-time.Second)
		}
	}
	f.srv.mu.Unlock()

	list, err := f.m.Organization.Invitations(ctx, f.orgID)
	if err != nil {
		t.Fatalf("Invitations: %v", err)
	}
	if len(list.OrganizationInvitations) != 0 {
		t.Errorf("expired invitation still listed as pending: %+v", list.OrganizationInvitations)
	}

	_, err = f.m.Organization.Invitation(ctx, f.orgID, inv.GetID())
	assertStatus(t, err, http.StatusNotFound)
}

// TestInvitationAppMetadataRoundTrip covers the "possible simplification" in
// the design: if an invitation can carry app_metadata.org_roles directly, the
// native role carrier and the seeding Action both disappear. The mock has to
// preserve it either way.
func TestInvitationAppMetadataRoundTrip(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inv := f.invitation("metadata@example.test")
	inv.AppMetadata = map[string]any{
		"org_roles": map[string]any{f.orgID: "admin"},
	}
	inv.UserMetadata = map[string]any{"invited_by": "platform"}

	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	read, err := f.m.Organization.Invitation(ctx, f.orgID, inv.GetID())
	if err != nil {
		t.Fatalf("Invitation: %v", err)
	}

	orgRoles, ok := read.AppMetadata["org_roles"].(map[string]any)
	if !ok {
		t.Fatalf("app_metadata.org_roles dropped or wrong type: %#v", read.AppMetadata["org_roles"])
	}
	if orgRoles[f.orgID] != "admin" {
		t.Errorf("org_roles[%s] = %v, want admin", f.orgID, orgRoles[f.orgID])
	}
	if read.UserMetadata["invited_by"] != "platform" {
		t.Errorf("user_metadata lost: %#v", read.UserMetadata)
	}
}

// TestInvitationsAreOrgScoped guards against invitations leaking across
// organizations, since every route is org-scoped.
func TestInvitationsAreOrgScoped(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	other := "other-org"
	otherOrg := &management.Organization{Name: &other}
	if err := f.m.Organization.Create(ctx, otherOrg); err != nil {
		t.Fatalf("Organization.Create: %v", err)
	}

	inv := f.invitation("scoped@example.test")
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	// Readable in its own organization, absent from the other.
	if _, err := f.m.Organization.Invitation(ctx, f.orgID, inv.GetID()); err != nil {
		t.Fatalf("Invitation in own org: %v", err)
	}
	_, err := f.m.Organization.Invitation(ctx, otherOrg.GetID(), inv.GetID())
	assertStatus(t, err, http.StatusNotFound)

	// And not revocable through the wrong organization.
	err = f.m.Organization.DeleteInvitation(ctx, otherOrg.GetID(), inv.GetID())
	assertStatus(t, err, http.StatusNotFound)
	if _, err := f.m.Organization.Invitation(ctx, f.orgID, inv.GetID()); err != nil {
		t.Fatalf("invitation revoked through the wrong organization: %v", err)
	}

	list, err := f.m.Organization.Invitations(ctx, otherOrg.GetID())
	if err != nil {
		t.Fatalf("Invitations on other org: %v", err)
	}
	if len(list.OrganizationInvitations) != 0 {
		t.Errorf("invitation leaked into another organization: %+v", list.OrganizationInvitations)
	}
}

// TestDeletingOrganizationDropsInvitations keeps revoked-by-teardown state
// from outliving its organization.
func TestDeletingOrganizationDropsInvitations(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inv := f.invitation("orphan@example.test")
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if err := f.m.Organization.Delete(ctx, f.orgID); err != nil {
		t.Fatalf("Organization.Delete: %v", err)
	}

	f.srv.mu.RLock()
	left := len(f.srv.invitations[f.orgID])
	f.srv.mu.RUnlock()
	if left != 0 {
		t.Errorf("%d invitations outlived their organization", left)
	}
}

// TestInvitationURLConstruction covers the login URIs a real SPA configures.
// The hash-routed case is the one string concatenation gets wrong: appending
// "?invitation=..." after a "#" buries the parameters in the fragment, where
// the browser never exposes them as query values.
func TestInvitationURLConstruction(t *testing.T) {
	org := &config.Organization{ID: "org_a", Name: "acme"}

	tests := []struct {
		name             string
		initiateLoginURI string
	}{
		{"plain path", "https://app.test/login"},
		{"existing query", "https://app.test/login?tenant=x"},
		{"trailing slash", "https://app.test/"},
		{"bare host", "https://app.test"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := invitationURL(tc.initiateLoginURI, "tkt_1", org, "")
			if err != nil {
				t.Fatalf("invitationURL: %v", err)
			}

			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("result not parseable: %v", err)
			}
			q := u.Query()
			if q.Get("invitation") != "tkt_1" {
				t.Errorf("invitation param missing from the query: %q", got)
			}
			if q.Get("organization") != "org_a" {
				t.Errorf("organization param missing from the query: %q", got)
			}
			if q.Get("organization_name") != "acme" {
				t.Errorf("organization_name param missing from the query: %q", got)
			}
			if u.Fragment != "" {
				t.Errorf("unexpected fragment %q in %q", u.Fragment, got)
			}
		})
	}

	t.Run("preserves an existing query parameter", func(t *testing.T) {
		got, err := invitationURL("https://app.test/login?tenant=x", "tkt_1", org, "")
		if err != nil {
			t.Fatalf("invitationURL: %v", err)
		}
		u, _ := url.Parse(got)
		if u.Query().Get("tenant") != "x" {
			t.Errorf("existing query parameter lost: %q", got)
		}
	})

	t.Run("rejects uris that cannot root a followable link", func(t *testing.T) {
		// url.Parse accepts all of these, so parse-error checking alone is
		// not enough to keep a useless invitation_url from being minted.
		// go-auth0 documents the field as "must be https and cannot contain a
		// fragment", so http and hash-routed URIs are refused too.
		for _, bad := range []string{
			"http://[::1",              // unparseable
			"/login",                   // relative path
			"login",                    // bare relative reference
			"//app.test/login",         // protocol-relative, no scheme
			"app.test/login",           // no scheme
			"ftp://app.test",           // wrong scheme
			"mailto:a@b.test",          // opaque, no host
			"https://",                 // scheme with no host
			"http://app.test/login",    // http, not https
			"https://app.test/#/login", // fragment
			"https://app.test/login#x", // fragment
		} {
			if _, err := invitationURL(bad, "tkt_1", org, ""); err == nil {
				t.Errorf("expected %q to be rejected as an initiate_login_uri", bad)
			}
		}
	})
}

// TestClientRejectsInvalidInitiateLoginURI pins the field's contract at the
// point it is set, so a client that real Auth0 would refuse cannot be stored
// and only fail later when someone tries to invite through it.
func TestClientRejectsInvalidInitiateLoginURI(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	for _, bad := range []string{
		"/login",
		"http://app.example.test/login",
		"https://app.example.test/#/login",
		"http://[::1",
	} {
		t.Run("create "+bad, func(t *testing.T) {
			err := f.m.Client.Create(ctx, &management.Client{
				Name:             auth0String("Bad URI " + bad),
				AppType:          auth0String("spa"),
				InitiateLoginURI: auth0String(bad),
			})
			assertStatus(t, err, http.StatusBadRequest)
		})

		t.Run("update "+bad, func(t *testing.T) {
			err := f.m.Client.Update(ctx, f.clientID,
				&management.Client{InitiateLoginURI: auth0String(bad)})
			assertStatus(t, err, http.StatusBadRequest)

			// The rejected update must not have disturbed the stored value.
			read, err := f.m.Client.Read(ctx, f.clientID)
			if err != nil {
				t.Fatalf("Client.Read: %v", err)
			}
			if read.GetInitiateLoginURI() != f.loginURI {
				t.Errorf("initiate_login_uri = %q, want it left at %q",
					read.GetInitiateLoginURI(), f.loginURI)
			}
		})
	}
}

// TestRevokeExpiredInvitationIsOrderIndependent pins that revoking an expired
// invitation 404s whether or not a list or read pruned it first. Without the
// prune in delete, the same call returned 204 or 404 depending on ordering.
func TestRevokeExpiredInvitationIsOrderIndependent(t *testing.T) {
	expire := func(t *testing.T, f *inviteFixture, id string) {
		t.Helper()
		f.srv.mu.Lock()
		defer f.srv.mu.Unlock()
		for i := range f.srv.invitations[f.orgID] {
			if f.srv.invitations[f.orgID][i].ID == id {
				f.srv.invitations[f.orgID][i].ExpiresAt = time.Now().Add(-time.Second)
			}
		}
	}

	t.Run("WithoutAPriorRead", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()
		ctx := context.Background()

		inv := f.invitation("expired-a@example.test")
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		expire(t, f, inv.GetID())

		err := f.m.Organization.DeleteInvitation(ctx, f.orgID, inv.GetID())
		assertStatus(t, err, http.StatusNotFound)
	})

	t.Run("AfterAPriorRead", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()
		ctx := context.Background()

		inv := f.invitation("expired-b@example.test")
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		expire(t, f, inv.GetID())

		// The read prunes it; the delete must agree.
		_, err := f.m.Organization.Invitation(ctx, f.orgID, inv.GetID())
		assertStatus(t, err, http.StatusNotFound)

		err = f.m.Organization.DeleteInvitation(ctx, f.orgID, inv.GetID())
		assertStatus(t, err, http.StatusNotFound)
	})
}

// TestClientInitiateLoginURICanBeCleared covers PATCH semantics: sending an
// empty value must remove the URI, not be mistaken for an omitted field and
// leave the old endpoint live for later invitations.
func TestClientInitiateLoginURICanBeCleared(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	name := "Clearable SPA"
	appType := "spa"
	loginURI := "https://app.example.test/login"
	c := &management.Client{Name: &name, AppType: &appType, InitiateLoginURI: &loginURI}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Client.Create: %v", err)
	}

	cleared := ""
	if err := m.Client.Update(ctx, c.GetClientID(),
		&management.Client{InitiateLoginURI: &cleared}); err != nil {
		t.Fatalf("Client.Update: %v", err)
	}

	read, err := m.Client.Read(ctx, c.GetClientID())
	if err != nil {
		t.Fatalf("Client.Read: %v", err)
	}
	if read.GetInitiateLoginURI() != "" {
		t.Errorf("initiate_login_uri = %q, want it cleared", read.GetInitiateLoginURI())
	}

	// An omitted field must still leave the value alone.
	if err := m.Client.Update(ctx, c.GetClientID(), &management.Client{InitiateLoginURI: &loginURI}); err != nil {
		t.Fatalf("Client.Update restore: %v", err)
	}
	newDesc := "described"
	if err := m.Client.Update(ctx, c.GetClientID(), &management.Client{Description: &newDesc}); err != nil {
		t.Fatalf("Client.Update description only: %v", err)
	}
	read2, err := m.Client.Read(ctx, c.GetClientID())
	if err != nil {
		t.Fatalf("Client.Read: %v", err)
	}
	if read2.GetInitiateLoginURI() != loginURI {
		t.Errorf("an omitted field was cleared: %q", read2.GetInitiateLoginURI())
	}
	if read2.GetDescription() != newDesc {
		t.Errorf("description = %q, want %q", read2.GetDescription(), newDesc)
	}
}

// TestInvitationRejectsConnectionNotEnabledOnOrg covers a named connection
// that exists and is non-passwordless but is not enabled on the organization:
// the invitation would force the invitee through a connection the org cannot
// authenticate against.
func TestInvitationRejectsConnectionNotEnabledOnOrg(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	// A non-passwordless connection that is never enabled on the org.
	name := "unrelated-oidc"
	strategy := "oidc"
	conn := &management.Connection{Name: &name, Strategy: &strategy}
	if err := f.m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Connection.Create: %v", err)
	}

	inv := f.invitation("stranded@example.test")
	inv.ConnectionID = conn.ID
	err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
	assertStatus(t, err, http.StatusBadRequest)

	// Enabling it makes the same request valid.
	if err := f.m.Organization.AddConnection(ctx, f.orgID,
		&management.OrganizationConnection{ConnectionID: conn.ID}); err != nil {
		t.Fatalf("Organization.AddConnection: %v", err)
	}
	inv2 := f.invitation("stranded@example.test")
	inv2.ConnectionID = conn.ID
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv2); err != nil {
		t.Fatalf("CreateInvitation once the connection is enabled: %v", err)
	}
}

// TestRejectedInvitationIsNotStored keeps a refused create from leaving a
// half-made invitation behind.
func TestRejectedInvitationIsNotStored(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inv := f.invitation("rejected@example.test")
	inv.Roles = []string{"rol_nope"}
	err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
	assertStatus(t, err, http.StatusBadRequest)

	f.srv.mu.RLock()
	pending := len(f.srv.invitations[f.orgID])
	f.srv.mu.RUnlock()
	if pending != 0 {
		t.Errorf("a rejected invitation was still stored (%d pending)", pending)
	}
}
