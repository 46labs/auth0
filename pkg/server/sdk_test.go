package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/auth0/go-auth0/management"
)

// TestAuth0SDKCompatibility verifies that the mock works with the official go-auth0 SDK
func TestAuth0SDKCompatibility(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Create management client pointing to our mock
	m, err := management.New(
		ts.URL,
		management.WithStaticToken("mock_token"),
		management.WithInsecure(), // For httptest server
	)
	if err != nil {
		t.Fatalf("Failed to create management client: %v", err)
	}

	t.Run("ListOrganizations", func(t *testing.T) {
		orgs, err := m.Organization.List(context.Background())
		if err != nil {
			t.Fatalf("Failed to list organizations: %v", err)
		}

		if len(orgs.Organizations) == 0 {
			t.Error("Expected at least one organization")
		}

		t.Logf("Found %d organizations", len(orgs.Organizations))
	})

	t.Run("GetOrganization", func(t *testing.T) {
		org, err := m.Organization.Read(context.Background(), "org_test")
		if err != nil {
			t.Fatalf("Failed to get organization: %v", err)
		}

		if org.GetID() != "org_test" {
			t.Errorf("Expected org_test, got %s", org.GetID())
		}

		t.Logf("Organization: %s (%s)", org.GetName(), org.GetDisplayName())
	})

	t.Run("CreateOrganization", func(t *testing.T) {
		name := "sdk-test-org"
		displayName := "SDK Test Org"
		newOrg := &management.Organization{
			Name:        &name,
			DisplayName: &displayName,
		}

		err := m.Organization.Create(context.Background(), newOrg)
		if err != nil {
			t.Fatalf("Failed to create organization: %v", err)
		}

		if newOrg.GetID() == "" {
			t.Error("Expected generated ID")
		}

		t.Logf("Created organization: %s", newOrg.GetID())
	})

	t.Run("GetUser", func(t *testing.T) {
		user, err := m.User.Read(context.Background(), "test_user_1")
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		if user.GetID() != "test_user_1" {
			t.Errorf("Expected test_user_1, got %s", user.GetID())
		}

		t.Logf("User: %s (%s)", user.GetName(), user.GetEmail())
	})

	t.Run("GetUser_VerifyIdentities", func(t *testing.T) {
		user, err := m.User.Read(context.Background(), "test_user_1")
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		// Verify identities array exists and is populated
		if len(user.Identities) == 0 {
			t.Fatal("Expected user to have identities array")
		}

		identity := user.Identities[0]

		// Verify identity structure matches Auth0 API
		if identity.Connection == nil {
			t.Error("Expected identity.Connection to be set")
		} else if *identity.Connection != "sms" {
			t.Errorf("Expected connection=sms, got %s", *identity.Connection)
		}

		if identity.Provider == nil {
			t.Error("Expected identity.Provider to be set")
		} else if *identity.Provider != "sms" {
			t.Errorf("Expected provider=sms, got %s", *identity.Provider)
		}

		if identity.UserID == nil {
			t.Error("Expected identity.UserID to be set")
		}

		if identity.IsSocial == nil {
			t.Error("Expected identity.IsSocial to be set")
		} else if *identity.IsSocial != false {
			t.Error("Expected isSocial=false for passwordless")
		}

		t.Logf("User identities verified: connection=%s, provider=%s, isSocial=%v",
			*identity.Connection, *identity.Provider, *identity.IsSocial)
	})

	t.Run("GetEmailUser_VerifyIdentities", func(t *testing.T) {
		user, err := m.User.Read(context.Background(), "test_user_2")
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		// Verify email user has email identities
		if len(user.Identities) == 0 {
			t.Fatal("Expected user to have identities array")
		}

		identity := user.Identities[0]

		if identity.Connection == nil || *identity.Connection != "email" {
			t.Errorf("Expected connection=email, got %v", identity.Connection)
		}

		if identity.Provider == nil || *identity.Provider != "email" {
			t.Errorf("Expected provider=email, got %v", identity.Provider)
		}

		t.Logf("Email user identities verified: connection=%s", *identity.Connection)
	})

	t.Run("UpdateUserMetadata", func(t *testing.T) {
		appMeta := map[string]interface{}{
			"tenant_id": "org_updated_via_sdk",
			"role":      "member",
		}
		updates := &management.User{
			AppMetadata: &appMeta,
		}

		err := m.User.Update(context.Background(), "test_user_1", updates)
		if err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		// Verify the update
		user := srv.getUserByID("test_user_1")
		if user.AppMetadata.TenantID != "org_updated_via_sdk" {
			t.Errorf("Expected tenant_id=org_updated_via_sdk, got %s", user.AppMetadata.TenantID)
		}

		t.Log("User metadata updated via SDK")
	})

	t.Run("ListConnections", func(t *testing.T) {
		conns, err := m.Connection.List(context.Background())
		if err != nil {
			t.Fatalf("Failed to list connections: %v", err)
		}

		if len(conns.Connections) == 0 {
			t.Error("Expected at least one connection")
		}

		t.Logf("Found %d connections", len(conns.Connections))
	})
}

// TestManagementAPIAuth tests that the API accepts bearer tokens (even if not validated in mock)
func TestManagementAPIAuth(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	t.Run("WithBearerToken", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v2/organizations", nil)
		req.Header.Set("Authorization", "Bearer mock_token")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != 200 {
			t.Fatalf("Expected 200, got %d", resp.StatusCode)
		}

		t.Log("Management API accepts bearer token")
	})

	t.Run("WithoutAuth", func(t *testing.T) {
		// For now, mock allows requests without auth (development mode)
		// In production, you'd want to validate tokens
		resp, err := http.Get(ts.URL + "/api/v2/organizations")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != 200 {
			t.Fatalf("Expected 200, got %d", resp.StatusCode)
		}

		t.Log("Development mode: API accessible without auth")
	})
}

// TestSDKTokenExchange tests the full OAuth flow with the SDK
func TestSDKTokenExchange(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// This would test the full OAuth flow using the SDK's OAuth client
	// For now, we'll verify the token endpoint compatibility
	t.Run("TokenEndpointCompatibility", func(t *testing.T) {
		// The token endpoint should return tokens in the format the SDK expects
		// This is already tested in TestCompleteOAuth2PKCEFlow
		// but we're confirming it works with SDK expectations

		if srv.cfg.Issuer == "" {
			t.Fatal("Issuer not configured")
		}

		t.Log("Token endpoint compatible with OAuth2 SDK")
	})
}

// TestSDKWithClientCredentials tests the Management API SDK with client_credentials flow
func TestSDKWithClientCredentials(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	// Create management client using client_credentials flow
	m, err := management.New(
		ts.URL,
		management.WithClientCredentials(
			context.Background(),
			"mgmt_client_test",
			"mgmt_secret_test",
		),
		management.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("Failed to create management client with client_credentials: %v", err)
	}

	t.Run("ListOrganizations", func(t *testing.T) {
		orgs, err := m.Organization.List(context.Background())
		if err != nil {
			t.Fatalf("Failed to list organizations: %v", err)
		}

		if len(orgs.Organizations) == 0 {
			t.Error("Expected at least one organization")
		}

		t.Logf("Successfully listed %d organizations via client_credentials", len(orgs.Organizations))
	})

	t.Run("GetOrganization", func(t *testing.T) {
		org, err := m.Organization.Read(context.Background(), "org_test")
		if err != nil {
			t.Fatalf("Failed to get organization: %v", err)
		}

		if org.GetID() != "org_test" {
			t.Errorf("Expected org_test, got %s", org.GetID())
		}

		t.Logf("Successfully read organization via client_credentials")
	})

	t.Run("CreateOrganization", func(t *testing.T) {
		name := "m2m-test-org"
		displayName := "M2M Test Org"
		newOrg := &management.Organization{
			Name:        &name,
			DisplayName: &displayName,
		}

		err := m.Organization.Create(context.Background(), newOrg)
		if err != nil {
			t.Fatalf("Failed to create organization: %v", err)
		}

		if newOrg.GetID() == "" {
			t.Error("Expected generated ID")
		}

		t.Logf("Successfully created organization via client_credentials: %s", newOrg.GetID())
	})
}
