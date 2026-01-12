package server

import (
	"context"
	"testing"

	"github.com/46labs/auth0/pkg/config"
	"github.com/auth0/go-auth0/management"
)

// TestClientCredentialsFlow tests using WithClientCredentials like the nextel API does
func TestClientCredentialsFlow(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// First add a user that we'll try to add to the organization
	srv.mu.Lock()
	srv.users["auth0|testuser123"] = &config.User{
		ID:            "auth0|testuser123",
		Phone:         "+14155551234",
		Name:          "+14155551234",
		EmailVerified: false,
	}
	srv.mu.Unlock()

	// Test with plain httptest URL first
	t.Log("Testing with httptest URL:", ts.URL)
	mgmt, err := management.New(
		ts.URL,
		management.WithClientCredentials(context.Background(), "mgmt_client_dev", "mgmt_secret_dev"),
		management.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("Failed to create management client with httptest URL: %v", err)
	}

	// Try adding member with httptest URL
	err = mgmt.Organization.AddMembers(context.Background(), "org_test", []string{"auth0|testuser123"})
	if err != nil {
		t.Fatalf("Failed to add member with httptest URL: %v", err)
	}
	t.Log("✓ httptest URL works")

	// Now test with HTTPS-formatted URL (like production)
	httpsURL := "https" + ts.URL[4:] // Change http to https
	t.Log("Testing with HTTPS URL:", httpsURL)
	mgmt2, err := management.New(
		httpsURL,
		management.WithClientCredentials(context.Background(), "mgmt_client_dev", "mgmt_secret_dev"),
		management.WithInsecure(),
	)
	if err != nil {
		t.Fatalf("Failed to create management client with HTTPS URL: %v", err)
	}

	// Try adding member with HTTPS URL
	err = mgmt2.Organization.AddMembers(context.Background(), "org_test", []string{"auth0|testuser123"})
	if err != nil {
		t.Fatalf("Failed to add member with HTTPS URL: %v", err)
	}
	t.Log("✓ HTTPS URL works")
	t.Log("Successfully tested both HTTP and HTTPS URLs with WithClientCredentials")
}
