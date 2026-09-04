package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
)

// Driven through the official SDK rather than hand-rolled HTTP: the wire shapes
// only matter insofar as go-auth0 decodes them, and the consumer that needs
// these endpoints reaches them through exactly these methods.
func connMgmt(t *testing.T) (*Server, *management.Management) {
	t.Helper()
	srv, ts := setupTestServer(t)
	t.Cleanup(ts.Close)

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	return srv, m
}

func TestConnectionRead(t *testing.T) {
	_, m := connMgmt(t)

	got, err := m.Connection.Read(context.Background(), "con_sms")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.GetName() != "sms" || got.GetStrategy() != "sms" {
		t.Fatalf("unexpected connection: %+v", got)
	}
}

func TestConnectionReadUnknownIs404(t *testing.T) {
	_, m := connMgmt(t)

	_, err := m.Connection.Read(context.Background(), "con_nope")
	assertStatus(t, err, http.StatusNotFound)
}

// Auth0 replaces options wholesale rather than merging, so a caller correcting
// one OIDC field must send the whole block. Merging here would hide that until
// production.
func TestConnectionUpdateReplacesOptions(t *testing.T) {
	_, m := connMgmt(t)
	ctx := context.Background()

	created := &management.Connection{
		Name:     auth0.String("enterprise-x"),
		Strategy: auth0.String("oidc"),
		Options: &management.ConnectionOptionsOIDC{
			ClientID:     auth0.String("old-client"),
			DiscoveryURL: auth0.String("https://old.example.test/.well-known/openid-configuration"),
		},
	}
	if err := m.Connection.Create(ctx, created); err != nil {
		t.Fatalf("Create: %v", err)
	}

	patch := &management.Connection{
		Options: &management.ConnectionOptionsOIDC{
			ClientID:     auth0.String("new-client"),
			DiscoveryURL: auth0.String("https://new.example.test/.well-known/openid-configuration"),
		},
	}
	if err := m.Connection.Update(ctx, created.GetID(), patch); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := m.Connection.Read(ctx, created.GetID())
	if err != nil {
		t.Fatalf("Read after update: %v", err)
	}
	opts, ok := got.Options.(*management.ConnectionOptionsOIDC)
	if !ok {
		t.Fatalf("options decoded as %T", got.Options)
	}
	if opts.GetClientID() != "new-client" {
		t.Fatalf("client id = %q, want new-client", opts.GetClientID())
	}
	// Immutable in Auth0; a patch must not rename the connection.
	if got.GetName() != "enterprise-x" {
		t.Fatalf("name changed to %q", got.GetName())
	}
}

func TestConnectionUpdateUnknownIs404(t *testing.T) {
	_, m := connMgmt(t)

	err := m.Connection.Update(context.Background(), "con_nope", &management.Connection{
		DisplayName: auth0.String("x"),
	})
	assertStatus(t, err, http.StatusNotFound)
}

// A connection must be enabled on both its organization and the application
// that calls /authorize. Enabling only the organization fails the login, so
// this subresource is what makes runtime provisioning usable at all.
func TestConnectionEnabledClientsRoundTrip(t *testing.T) {
	_, m := connMgmt(t)
	ctx := context.Background()

	conn := &management.Connection{
		Name:     auth0.String("enterprise-clients"),
		Strategy: auth0.String("oidc"),
	}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := m.Connection.UpdateEnabledClients(ctx, conn.GetID(), []management.ConnectionEnabledClient{
		{ClientID: auth0.String("mgmt_client_test"), Status: auth0.Bool(true)},
	}); err != nil {
		t.Fatalf("UpdateEnabledClients: %v", err)
	}

	list, err := m.Connection.ReadEnabledClients(ctx, conn.GetID())
	if err != nil {
		t.Fatalf("ReadEnabledClients: %v", err)
	}
	if got := list.GetClients(); len(got) != 1 || got[0].GetClientID() != "mgmt_client_test" {
		t.Fatalf("unexpected clients: %+v", got)
	}

	// status false removes, and an omitted client is left alone.
	if err := m.Connection.UpdateEnabledClients(ctx, conn.GetID(), []management.ConnectionEnabledClient{
		{ClientID: auth0.String("mgmt_client_test"), Status: auth0.Bool(false)},
	}); err != nil {
		t.Fatalf("UpdateEnabledClients disable: %v", err)
	}
	list, err = m.Connection.ReadEnabledClients(ctx, conn.GetID())
	if err != nil {
		t.Fatalf("ReadEnabledClients after disable: %v", err)
	}
	if got := list.GetClients(); len(got) != 0 {
		t.Fatalf("expected no clients, got %+v", got)
	}
}

// The delta semantics matter: treating the array as the whole set would drop
// clients the caller never mentioned.
func TestConnectionEnabledClientsIsADelta(t *testing.T) {
	srv, m := connMgmt(t)
	ctx := context.Background()

	conn := &management.Connection{
		Name:           auth0.String("enterprise-delta"),
		Strategy:       auth0.String("oidc"),
		EnabledClients: &[]string{"mgmt_client_dev"},
	}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := m.Connection.UpdateEnabledClients(ctx, conn.GetID(), []management.ConnectionEnabledClient{
		{ClientID: auth0.String("mgmt_client_test"), Status: auth0.Bool(true)},
	}); err != nil {
		t.Fatalf("UpdateEnabledClients: %v", err)
	}

	srv.mu.RLock()
	got := append([]string(nil), srv.connections[conn.GetID()].EnabledClients...)
	srv.mu.RUnlock()

	if len(got) != 2 {
		t.Fatalf("expected both clients enabled, got %v", got)
	}
}

func TestConnectionEnabledClientsRejectsUnknownClient(t *testing.T) {
	_, m := connMgmt(t)

	err := m.Connection.UpdateEnabledClients(context.Background(), "con_sms", []management.ConnectionEnabledClient{
		{ClientID: auth0.String("not_a_client"), Status: auth0.Bool(true)},
	})
	assertStatus(t, err, http.StatusBadRequest)
}

// Deleting a connection must also drop the organization pairings that named it.
// A pairing left pointing at a deleted connection reads as a working login path
// right up until someone tries it.
func TestConnectionDeleteRemovesOrgPairings(t *testing.T) {
	srv, m := connMgmt(t)
	ctx := context.Background()

	conn := &management.Connection{Name: auth0.String("enterprise-doomed"), Strategy: auth0.String("oidc")}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Organization.AddConnection(ctx, "org_test", &management.OrganizationConnection{
		ConnectionID:            auth0.String(conn.GetID()),
		AssignMembershipOnLogin: auth0.Bool(true),
	}); err != nil {
		t.Fatalf("AddConnection: %v", err)
	}

	if err := m.Connection.Delete(ctx, conn.GetID()); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()
	for _, p := range srv.orgConnections["org_test"] {
		if p.ConnectionID == conn.GetID() {
			t.Fatal("organization still enables the deleted connection")
		}
	}
	if _, ok := srv.connections[conn.GetID()]; ok {
		t.Fatal("connection survived delete")
	}
}

// The routing trap this file exists to avoid: an unimplemented subresource must
// 404, not truncate to the parent and delete the connection.
func TestConnectionUnknownSubresourceDoesNotDeleteTheConnection(t *testing.T) {
	srv, _ := connMgmt(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v2/connections/con_sms/scim-configuration", nil)
	rec := httptest.NewRecorder()
	srv.handleConnection(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if _, ok := srv.connections["con_sms"]; !ok {
		t.Fatal("an unimplemented subresource deleted the connection")
	}
}
