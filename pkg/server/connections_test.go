package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Auth0 answers 202 with a deleted_at body, not 204
// (TestConnectionManager_Delete.yaml). A status-aware consumer sees different
// behaviour locally otherwise.
func TestConnectionDeleteUsesRecordedStatus(t *testing.T) {
	srv, m := connMgmt(t)
	ctx := context.Background()

	conn := &management.Connection{Name: auth0.String("enterprise-status"), Strategy: auth0.String("oidc")}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v2/connections/"+conn.GetID(), nil)
	rec := httptest.NewRecorder()
	srv.handleConnection(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["deleted_at"] == "" {
		t.Fatalf("expected a deleted_at body, got %s", rec.Body.String())
	}
}

// The SDK documents Delete as removing the connection and all its users.
// Leaving them behind keeps them readable and able to authenticate.
func TestConnectionDeleteRemovesItsUsers(t *testing.T) {
	srv, m := connMgmt(t)

	srv.mu.RLock()
	_, hadUser := srv.users["test_user_1"]
	srv.mu.RUnlock()
	if !hadUser {
		t.Skip("fixture user absent")
	}

	// test_user_1's identity is on the sms connection.
	if err := m.Connection.Delete(context.Background(), "con_sms"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if _, ok := srv.users["test_user_1"]; ok {
		t.Fatal("user on the deleted connection survived")
	}
	for orgID, ms := range srv.members {
		for _, m := range ms {
			if m.UserID == "test_user_1" {
				t.Fatalf("org %s still lists the deleted user as a member", orgID)
			}
		}
	}
}

// Auth0's GET carries client_id only. Echoing status back makes the SDK's
// GetStatus() report true locally and false against Auth0.
func TestConnectionEnabledClientsReadOmitsStatus(t *testing.T) {
	srv, _ := connMgmt(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/connections/con_email/clients", nil)
	rec := httptest.NewRecorder()
	srv.handleConnection(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "status") {
		t.Fatalf("response carries a status field Auth0 omits: %s", rec.Body.String())
	}
}

// Accepting metadata and dropping it would answer 200 while the next read loses
// the write.
func TestConnectionUpdateRejectsUnsupportedMetadata(t *testing.T) {
	srv, _ := connMgmt(t)

	req := httptest.NewRequest(http.MethodPatch, "/api/v2/connections/con_sms",
		strings.NewReader(`{"metadata":{"k":"v"}}`))
	rec := httptest.NewRecorder()
	srv.handleConnection(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// Auth0 records a repeated delete of the same id as 204 with an empty body, so
// retried cleanup must not look like a different outcome locally.
func TestConnectionDeleteIsIdempotent(t *testing.T) {
	srv, m := connMgmt(t)
	ctx := context.Background()

	conn := &management.Connection{Name: auth0.String("enterprise-twice"), Strategy: auth0.String("oidc")}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Connection.Delete(ctx, conn.GetID()); err != nil {
		t.Fatalf("first Delete: %v", err)
	}
	if err := m.Connection.Delete(ctx, conn.GetID()); err != nil {
		t.Fatalf("repeated Delete should be a no-op, got: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v2/connections/"+conn.GetID(), nil)
	rec := httptest.NewRecorder()
	srv.handleConnection(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("repeat status = %d, want 204", rec.Code)
	}
}

// A field the mock cannot persist must be refused, not accepted and dropped:
// answering 200 makes a provisioning run look converged when nothing changed.
func TestConnectionUpdateRejectsUnpersistedFields(t *testing.T) {
	srv, _ := connMgmt(t)

	for _, body := range []string{
		`{"metadata":{"k":"v"}}`,
		`{"realms":["x"]}`,
		`{"show_as_button":true}`,
	} {
		req := httptest.NewRequest(http.MethodPatch, "/api/v2/connections/con_sms", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.handleConnection(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", body, rec.Code)
		}
	}
}

// The SDK omits status when the caller leaves it nil. Decoding into a plain
// bool would read that as "disable" and answer 204.
func TestConnectionEnabledClientsRequiresStatus(t *testing.T) {
	srv, _ := connMgmt(t)

	req := httptest.NewRequest(http.MethodPatch, "/api/v2/connections/con_sms/clients",
		strings.NewReader(`[{"client_id":"mgmt_client_test"}]`))
	rec := httptest.NewRecorder()
	srv.handleConnection(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// An invitee redeeming through an enterprise connection must carry that
// connection on their identity, or deleting it leaves them behind.
//
// Asserts on the STORED user, not the returned pointer: an earlier version
// stamped the identity in a defer that ran after the clone, so the return value
// looked right while the stored copy kept the inferred email identity, and a
// test reading the return value passed while delete still missed the user.
func TestAutoCreatedUserRecordsItsConnection(t *testing.T) {
	srv, _ := connMgmt(t)

	srv.mu.Lock()
	u := srv.autoCreateUserOnConnectionLocked("enterprise.user@example.test", "enterprise-sso", "oidc")
	stored := srv.users[u.ID]
	srv.mu.Unlock()

	if len(stored.Identities) != 1 {
		t.Fatalf("stored identities = %+v", stored.Identities)
	}
	got := stored.Identities[0]
	if got.Connection != "enterprise-sso" {
		t.Fatalf("stored connection = %q, want enterprise-sso", got.Connection)
	}
	// Auth0 reports the strategy as the provider, not the connection name.
	if got.Provider != "oidc" {
		t.Fatalf("stored provider = %q, want oidc", got.Provider)
	}
}

// Disabling a client must actually stop it authenticating, not just read back
// as disabled.
func TestConnectionDisabledClientCannotAuthorize(t *testing.T) {
	srv, m := connMgmt(t)
	ctx := context.Background()

	conn := &management.Connection{
		Name:           auth0.String("enterprise-gate"),
		Strategy:       auth0.String("oidc"),
		EnabledClients: &[]string{"mgmt_client_dev"},
	}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if srv.connectionAllowsClient("enterprise-gate", "mgmt_client_test") {
		t.Fatal("a client absent from enabled_clients was allowed to authorize")
	}
	if !srv.connectionAllowsClient("enterprise-gate", "mgmt_client_dev") {
		t.Fatal("an enabled client was refused")
	}
	// The fixture convention: "*" means every client.
	if !srv.connectionAllowsClient("sms", "anything") {
		t.Fatal("the wildcard fixture connection refused a client")
	}
}
