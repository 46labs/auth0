package client

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/server"
)

func setupTestServer(t *testing.T) (*server.Server, *httptest.Server) {
	cfg := &config.Config{
		Issuer:      "http://localhost:4646/",
		Audience:    "http://localhost:3000",
		Port:        4646,
		CORSOrigins: []string{"*"},
		Organizations: []config.Organization{
			{
				ID:          "org_test",
				Name:        "test-org",
				DisplayName: "Test Organization",
			},
		},
	}

	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	cfg.Issuer = ts.URL + "/"

	return srv, ts
}

func TestClientAgainstMock(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Create client pointing to test server
	client, err := New(Config{
		Domain:       ts.URL,
		ClientID:     "test_client",
		ClientSecret: "test_secret",
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	t.Run("ListOrganizations", func(t *testing.T) {
		orgs, err := client.ListOrganizations(ctx)
		if err != nil {
			t.Fatalf("Failed to list organizations: %v", err)
		}

		if len(orgs) == 0 {
			t.Error("Expected at least one organization")
		}

		t.Logf("Listed %d organizations", len(orgs))
	})

	t.Run("GetOrganization", func(t *testing.T) {
		org, err := client.GetOrganization(ctx, "org_test")
		if err != nil {
			t.Fatalf("Failed to get organization: %v", err)
		}

		if org.GetID() != "org_test" {
			t.Errorf("Expected org_test, got %s", org.GetID())
		}

		t.Log("Successfully retrieved organization")
	})

	t.Run("CreateOrganization", func(t *testing.T) {
		metadata := map[string]string{
			"environment": "test",
		}

		org, err := client.CreateOrganization(ctx, "test-org-2", "Test Organization 2", metadata)
		if err != nil {
			t.Fatalf("Failed to create organization: %v", err)
		}

		if org.GetID() == "" {
			t.Error("Expected generated ID")
		}

		t.Logf("Created organization: %s", org.GetID())
	})

	t.Run("UpdateOrgMetadata", func(t *testing.T) {
		metadata := map[string]string{
			"updated": "true",
		}

		err := client.UpdateOrgMetadata(ctx, "org_test", metadata)
		if err != nil {
			t.Fatalf("Failed to update metadata: %v", err)
		}

		t.Log("Successfully updated organization metadata")
	})

	t.Run("AddUserToOrganization", func(t *testing.T) {
		// Create a test user in the mock server
		srv.SetUser("test_user_new", &config.User{
			ID:            "test_user_new",
			Email:         "newuser@test.example",
			Name:          "New Test User",
			EmailVerified: true,
		})

		// Add user to organization with admin role using SDK client
		err := client.AddUserToOrganization(ctx, "org_test", "test_user_new", "admin")
		if err != nil {
			t.Fatalf("Failed to add user to organization: %v", err)
		}

		// Verify the user was added by checking the member list
		members := srv.GetOrgMembers("org_test")
		found := false
		for _, member := range members {
			if member.UserID == "test_user_new" {
				found = true
				if member.Role != "admin" {
					t.Errorf("Expected role=admin, got %s", member.Role)
				}
				break
			}
		}

		if !found {
			t.Error("User was not added to organization")
		}

		t.Log("Successfully added user to organization with role")
	})
}
