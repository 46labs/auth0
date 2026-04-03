package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/46labs/auth0/pkg/config"
	"github.com/auth0/go-auth0/management"
	"github.com/golang-jwt/jwt/v5"
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
	t.Log("httptest URL works")

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
	t.Log("HTTPS URL works")
}

// TestClientCredentialsWithOrganization verifies that passing the "organization"
// parameter in a client_credentials request produces a token with the "org_id" claim.
// This mirrors real Auth0 behavior for M2M tokens scoped to an organization.
func TestClientCredentialsWithOrganization(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	t.Run("organization param produces org_id claim", func(t *testing.T) {
		resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"mgmt_client_dev"},
			"client_secret": {"mgmt_secret_dev"},
			"audience":      {"http://localhost:3000"},
			"organization":  {"org_test"},
		})
		if err != nil {
			t.Fatalf("Token request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != 200 {
			t.Fatalf("Expected 200, got %d", resp.StatusCode)
		}

		var body struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		token, _, err := jwt.NewParser().ParseUnverified(body.AccessToken, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("Failed to parse token: %v", err)
		}

		claims := token.Claims.(jwt.MapClaims)
		orgID, ok := claims["org_id"]
		if !ok {
			t.Fatal("Expected org_id claim in token, not found")
		}
		if orgID != "org_test" {
			t.Errorf("Expected org_id=org_test, got %v", orgID)
		}

		// Verify other standard claims
		if claims["sub"] != "mgmt_client_dev" {
			t.Errorf("Expected sub=mgmt_client_dev, got %v", claims["sub"])
		}
		if claims["gty"] != "client-credentials" {
			t.Errorf("Expected gty=client-credentials, got %v", claims["gty"])
		}
	})

	t.Run("no organization param omits org_id claim", func(t *testing.T) {
		resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"mgmt_client_dev"},
			"client_secret": {"mgmt_secret_dev"},
			"audience":      {"http://localhost:3000"},
		})
		if err != nil {
			t.Fatalf("Token request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var body struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		token, _, err := jwt.NewParser().ParseUnverified(body.AccessToken, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("Failed to parse token: %v", err)
		}

		claims := token.Claims.(jwt.MapClaims)
		if _, ok := claims["org_id"]; ok {
			t.Error("Expected no org_id claim when organization not provided")
		}
	})

	t.Run("invalid organization returns error", func(t *testing.T) {
		resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"mgmt_client_dev"},
			"client_secret": {"mgmt_secret_dev"},
			"audience":      {"http://localhost:3000"},
			"organization":  {"org_nonexistent"},
		})
		if err != nil {
			t.Fatalf("Token request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != 400 {
			t.Errorf("Expected 400 for invalid organization, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid client secret returns 401", func(t *testing.T) {
		resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"mgmt_client_dev"},
			"client_secret": {"wrong_secret"},
			"audience":      {"http://localhost:3000"},
		})
		if err != nil {
			t.Fatalf("Token request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != 401 {
			t.Errorf("Expected 401 for invalid secret, got %d", resp.StatusCode)
		}
	})
}
