package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/46labs/auth0/pkg/config"
	"github.com/auth0/go-auth0/management"
)

// TestSDKOrganizationConnections drives the enabled_connections sub-resource
// through the official SDK, which is the only proof that the wire shapes match
// what a real client decodes.
func TestSDKOrganizationConnections(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	t.Run("ListSeededFromConnectionOrganizations", func(t *testing.T) {
		list, err := m.Organization.Connections(ctx, "org_test")
		if err != nil {
			t.Fatalf("Organization.Connections: %v", err)
		}
		if len(list.OrganizationConnections) == 0 {
			t.Fatal("expected pairings derived from each connection's organizations list")
		}

		// The nested connection details must be projected, since the
		// passwordless check and the login prompt both read the strategy.
		byID := map[string]*management.OrganizationConnection{}
		for _, oc := range list.OrganizationConnections {
			byID[oc.GetConnectionID()] = oc
		}
		sms, ok := byID["con_sms"]
		if !ok {
			t.Fatalf("con_sms not enabled on org_test: %+v", byID)
		}
		if sms.Connection == nil {
			t.Fatal("nested connection details missing")
		}
		if got := sms.Connection.GetStrategy(); got != "sms" {
			t.Errorf("expected strategy sms, got %q", got)
		}
		if got := sms.Connection.GetName(); got != "sms" {
			t.Errorf("expected name sms, got %q", got)
		}
	})

	t.Run("AddConnection", func(t *testing.T) {
		// A connection has to exist before it can be enabled.
		name := "corp-db"
		strategy := "auth0"
		conn := &management.Connection{Name: &name, Strategy: &strategy}
		if err := m.Connection.Create(ctx, conn); err != nil {
			t.Fatalf("Connection.Create: %v", err)
		}

		assign := true
		oc := &management.OrganizationConnection{
			ConnectionID:            conn.ID,
			AssignMembershipOnLogin: &assign,
		}
		if err := m.Organization.AddConnection(ctx, "org_test", oc); err != nil {
			t.Fatalf("Organization.AddConnection: %v", err)
		}
		if !oc.GetAssignMembershipOnLogin() {
			t.Error("assign_membership_on_login not echoed back")
		}

		read, err := m.Organization.Connection(ctx, "org_test", conn.GetID())
		if err != nil {
			t.Fatalf("Organization.Connection: %v", err)
		}
		if read.GetConnectionID() != conn.GetID() {
			t.Errorf("expected %q, got %q", conn.GetID(), read.GetConnectionID())
		}
		if read.Connection.GetStrategy() != "auth0" {
			t.Errorf("expected strategy auth0, got %q", read.Connection.GetStrategy())
		}
		// Auth0 defaults show_as_button to true.
		if !read.GetShowAsButton() {
			t.Error("expected show_as_button to default true")
		}
	})

	t.Run("AddConnectionRejectsUnknownConnection", func(t *testing.T) {
		unknown := "con_nope"
		err := m.Organization.AddConnection(ctx, "org_test",
			&management.OrganizationConnection{ConnectionID: &unknown})
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("AddConnectionRejectsDuplicate", func(t *testing.T) {
		existing := "con_sms"
		err := m.Organization.AddConnection(ctx, "org_test",
			&management.OrganizationConnection{ConnectionID: &existing})
		assertStatus(t, err, http.StatusConflict)
	})

	t.Run("AddConnectionUnknownOrg", func(t *testing.T) {
		existing := "con_sms"
		err := m.Organization.AddConnection(ctx, "org_missing",
			&management.OrganizationConnection{ConnectionID: &existing})
		assertStatus(t, err, http.StatusNotFound)
	})

	t.Run("UpdateConnection", func(t *testing.T) {
		assign := true
		show := false
		err := m.Organization.UpdateConnection(ctx, "org_test", "con_email",
			&management.OrganizationConnection{AssignMembershipOnLogin: &assign, ShowAsButton: &show})
		if err != nil {
			t.Fatalf("Organization.UpdateConnection: %v", err)
		}

		read, err := m.Organization.Connection(ctx, "org_test", "con_email")
		if err != nil {
			t.Fatalf("Organization.Connection: %v", err)
		}
		if !read.GetAssignMembershipOnLogin() {
			t.Error("assign_membership_on_login not persisted")
		}
		if read.GetShowAsButton() {
			t.Error("show_as_button=false not persisted")
		}
	})

	t.Run("DeleteConnection", func(t *testing.T) {
		name := "removable"
		strategy := "oidc"
		conn := &management.Connection{Name: &name, Strategy: &strategy}
		if err := m.Connection.Create(ctx, conn); err != nil {
			t.Fatalf("Connection.Create: %v", err)
		}
		if err := m.Organization.AddConnection(ctx, "org_test",
			&management.OrganizationConnection{ConnectionID: conn.ID}); err != nil {
			t.Fatalf("Organization.AddConnection: %v", err)
		}

		if err := m.Organization.DeleteConnection(ctx, "org_test", conn.GetID()); err != nil {
			t.Fatalf("Organization.DeleteConnection: %v", err)
		}

		_, err := m.Organization.Connection(ctx, "org_test", conn.GetID())
		assertStatus(t, err, http.StatusNotFound)
	})

	t.Run("ListUnknownOrg", func(t *testing.T) {
		_, err := m.Organization.Connections(ctx, "org_missing")
		assertStatus(t, err, http.StatusNotFound)
	})
}

// TestCreateOrganizationWithEnabledConnections covers the SDK-supported field
// on Organization.Create. Dropping it answered 201 with an organization that
// had no connections, so an invitation issued immediately afterwards failed
// for a reason the caller could not see.
func TestCreateOrganizationWithEnabledConnections(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	connName := "created-with-org"
	strategy := "oidc"
	conn := &management.Connection{Name: &connName, Strategy: &strategy}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Connection.Create: %v", err)
	}

	assign := true
	orgName := "org-with-connections"
	org := &management.Organization{
		Name: &orgName,
		EnabledConnections: []*management.OrganizationConnection{
			{ConnectionID: conn.ID, AssignMembershipOnLogin: &assign},
		},
	}
	if err := m.Organization.Create(ctx, org); err != nil {
		t.Fatalf("Organization.Create: %v", err)
	}

	list, err := m.Organization.Connections(ctx, org.GetID())
	if err != nil {
		t.Fatalf("Organization.Connections: %v", err)
	}
	if len(list.OrganizationConnections) != 1 {
		t.Fatalf("expected the pairing sent at creation to persist, got %d", len(list.OrganizationConnections))
	}
	got := list.OrganizationConnections[0]
	if got.GetConnectionID() != conn.GetID() {
		t.Errorf("connection_id = %q, want %q", got.GetConnectionID(), conn.GetID())
	}
	if !got.GetAssignMembershipOnLogin() {
		t.Error("assign_membership_on_login not persisted")
	}
	if !got.GetShowAsButton() {
		t.Error("show_as_button should default to true")
	}

	t.Run("UnknownConnectionRejected", func(t *testing.T) {
		bad := "con_nope"
		name := "org-bad-connection"
		err := m.Organization.Create(ctx, &management.Organization{
			Name:               &name,
			EnabledConnections: []*management.OrganizationConnection{{ConnectionID: &bad}},
		})
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("DuplicateConnectionRejected", func(t *testing.T) {
		name := "org-dup-connection"
		err := m.Organization.Create(ctx, &management.Organization{
			Name: &name,
			EnabledConnections: []*management.OrganizationConnection{
				{ConnectionID: conn.ID},
				{ConnectionID: conn.ID},
			},
		})
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("InvalidPairingRejected", func(t *testing.T) {
		signup := true
		name := "org-bad-pairing"
		err := m.Organization.Create(ctx, &management.Organization{
			Name: &name,
			EnabledConnections: []*management.OrganizationConnection{
				{ConnectionID: conn.ID, IsSignupEnabled: &signup},
			},
		})
		assertStatus(t, err, http.StatusBadRequest)
	})
}

// TestConfigDeclaredPairingMatchesAPIDefaults pins that a pairing declared in
// config reports the same way as one created over HTTP. show_as_button
// defaults to true, which a plain bool in the config struct would have
// silently reported as false.
func TestConfigDeclaredPairingMatchesAPIDefaults(t *testing.T) {
	cfg := &config.Config{
		Issuer: "http://localhost:4646/",
		Organizations: []config.Organization{
			{ID: "org_declared", Name: "declared-org"},
		},
		Connections: []config.Connection{
			{ID: "con_declared", Name: "declared", Strategy: "oidc"},
		},
		OrganizationConnections: []config.DeclaredOrganizationConnection{
			// show_as_button omitted on purpose.
			{OrgID: "org_declared", ConnectionID: "con_declared"},
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv.mu.RLock()
	pairings := srv.orgConnections["org_declared"]
	srv.mu.RUnlock()

	if len(pairings) != 1 {
		t.Fatalf("expected 1 declared pairing, got %d", len(pairings))
	}
	if !pairings[0].ShowAsButton {
		t.Error("show_as_button should default to true for a config-declared pairing")
	}

	explicitFalse := false
	cfg.OrganizationConnections[0].ShowAsButton = &explicitFalse
	srv2, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv2.mu.RLock()
	pairings2 := srv2.orgConnections["org_declared"]
	srv2.mu.RUnlock()
	if pairings2[0].ShowAsButton {
		t.Error("an explicit show_as_button: false must be honored")
	}
}

// TestClientPatchRejectsEmptyName covers the required-field guard alongside
// the pointer-based clear semantics: optional fields can be blanked, name
// cannot.
func TestClientPatchRejectsEmptyName(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	name := "Named Client"
	appType := "spa"
	c := &management.Client{Name: &name, AppType: &appType}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Client.Create: %v", err)
	}

	empty := ""
	err = m.Client.Update(ctx, c.GetClientID(), &management.Client{Name: &empty})
	assertStatus(t, err, http.StatusBadRequest)

	read, err := m.Client.Read(ctx, c.GetClientID())
	if err != nil {
		t.Fatalf("Client.Read: %v", err)
	}
	if read.GetName() != name {
		t.Errorf("name = %q, want it left at %q", read.GetName(), name)
	}
}

// TestOrgConnectionSignupRequiresMembership covers the constraint Auth0
// documents on this pairing: is_signup_enabled is only valid alongside
// assign_membership_on_login, otherwise a user could sign up into an
// organization they never become a member of.
func TestOrgConnectionSignupRequiresMembership(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	name := "db-conn"
	strategy := "auth0"
	conn := &management.Connection{Name: &name, Strategy: &strategy}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Connection.Create: %v", err)
	}

	yes, no := true, false

	t.Run("AddRejectsSignupWithoutMembership", func(t *testing.T) {
		err := m.Organization.AddConnection(ctx, "org_test", &management.OrganizationConnection{
			ConnectionID:    conn.ID,
			IsSignupEnabled: &yes,
		})
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("AddAcceptsSignupWithMembership", func(t *testing.T) {
		err := m.Organization.AddConnection(ctx, "org_test", &management.OrganizationConnection{
			ConnectionID:            conn.ID,
			IsSignupEnabled:         &yes,
			AssignMembershipOnLogin: &yes,
		})
		if err != nil {
			t.Fatalf("AddConnection: %v", err)
		}
	})

	// Patching either field alone must not be able to reach the invalid state.
	t.Run("PatchCannotDisableMembershipWhileSignupEnabled", func(t *testing.T) {
		err := m.Organization.UpdateConnection(ctx, "org_test", conn.GetID(),
			&management.OrganizationConnection{AssignMembershipOnLogin: &no})
		assertStatus(t, err, http.StatusBadRequest)

		// The rejected patch must not have been applied.
		read, err := m.Organization.Connection(ctx, "org_test", conn.GetID())
		if err != nil {
			t.Fatalf("Organization.Connection: %v", err)
		}
		if !read.GetAssignMembershipOnLogin() {
			t.Error("a rejected patch was applied anyway")
		}
		if !read.GetIsSignupEnabled() {
			t.Error("is_signup_enabled was clobbered by a rejected patch")
		}
	})

	t.Run("PatchCanDisableBothTogether", func(t *testing.T) {
		err := m.Organization.UpdateConnection(ctx, "org_test", conn.GetID(),
			&management.OrganizationConnection{IsSignupEnabled: &no, AssignMembershipOnLogin: &no})
		if err != nil {
			t.Fatalf("UpdateConnection: %v", err)
		}
		read, err := m.Organization.Connection(ctx, "org_test", conn.GetID())
		if err != nil {
			t.Fatalf("Organization.Connection: %v", err)
		}
		if read.GetIsSignupEnabled() || read.GetAssignMembershipOnLogin() {
			t.Error("both flags should now be false")
		}
	})

	t.Run("PatchRejectsEnablingSignupAlone", func(t *testing.T) {
		err := m.Organization.UpdateConnection(ctx, "org_test", conn.GetID(),
			&management.OrganizationConnection{IsSignupEnabled: &yes})
		assertStatus(t, err, http.StatusBadRequest)
	})
}

// TestHasNonPasswordlessConnection covers the gate Auth0 applies before an
// invitation may be created. The seeded local config has only email and SMS,
// both passwordless, which is exactly the situation the design calls out.
func TestHasNonPasswordlessConnection(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	srv.mu.RLock()
	seeded := srv.hasNonPasswordlessConnection("org_test")
	srv.mu.RUnlock()
	if seeded {
		t.Fatal("seeded org has only passwordless connections; expected false")
	}

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	name := "enterprise-sso"
	strategy := "oidc"
	conn := &management.Connection{Name: &name, Strategy: &strategy}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Connection.Create: %v", err)
	}
	if err := m.Organization.AddConnection(ctx, "org_test",
		&management.OrganizationConnection{ConnectionID: conn.ID}); err != nil {
		t.Fatalf("Organization.AddConnection: %v", err)
	}

	srv.mu.RLock()
	after := srv.hasNonPasswordlessConnection("org_test")
	srv.mu.RUnlock()
	if !after {
		t.Error("expected true once a non-passwordless connection is enabled")
	}
}

// TestClientInitiateLoginURI pins the field an invitation_url is built from.
func TestClientInitiateLoginURI(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	name := "SPA With Login URI"
	appType := "spa"
	loginURI := "https://app.example.test/login"
	c := &management.Client{Name: &name, AppType: &appType, InitiateLoginURI: &loginURI}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Client.Create: %v", err)
	}

	read, err := m.Client.Read(ctx, c.GetClientID())
	if err != nil {
		t.Fatalf("Client.Read: %v", err)
	}
	if read.GetInitiateLoginURI() != loginURI {
		t.Errorf("expected initiate_login_uri %q, got %q", loginURI, read.GetInitiateLoginURI())
	}

	updated := "https://app.example.test/start"
	if err := m.Client.Update(ctx, c.GetClientID(),
		&management.Client{InitiateLoginURI: &updated}); err != nil {
		t.Fatalf("Client.Update: %v", err)
	}
	read2, err := m.Client.Read(ctx, c.GetClientID())
	if err != nil {
		t.Fatalf("Client.Read after update: %v", err)
	}
	if read2.GetInitiateLoginURI() != updated {
		t.Errorf("expected updated initiate_login_uri %q, got %q", updated, read2.GetInitiateLoginURI())
	}
}
