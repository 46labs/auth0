package server

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/auth0/go-auth0/management"
)

// TestUnimplementedOrgSubresourceDoesNotMutateOrg pins the safety property
// behind the organization router: a request to a subresource the mock does not
// implement must 404, and must never resolve to the organization record.
//
// The regression this guards: DELETE .../organizations/{id}/invitations/{iid}
// used to truncate the path to {id}, delete the organization, and answer 204.
// A caller wiring up invitation revocation against local dev would have
// dropped the tenant and been told it succeeded.
func TestUnimplementedOrgSubresourceDoesNotMutateOrg(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	assertOrgPresent := func(t *testing.T, when string) {
		t.Helper()
		if _, err := m.Organization.Read(ctx, "org_test"); err != nil {
			t.Fatalf("organization destroyed %s: %v", when, err)
		}
	}

	assertOrgPresent(t, "before the test")

	t.Run("DeleteInvitation", func(t *testing.T) {
		err := m.Organization.DeleteInvitation(ctx, "org_test", "inv_bogus")
		assertStatus(t, err, http.StatusNotFound)
		assertOrgPresent(t, "after DeleteInvitation")
	})

	t.Run("ReadInvitation", func(t *testing.T) {
		inv, err := m.Organization.Invitation(ctx, "org_test", "inv_bogus")
		assertStatus(t, err, http.StatusNotFound)
		if inv != nil && inv.GetID() != "" {
			t.Errorf("expected no invitation, got id=%q (organization leaked as an invitation)", inv.GetID())
		}
	})

	t.Run("EnabledConnections", func(t *testing.T) {
		// Not implemented yet; must 404 rather than answer with the org.
		_, err := m.Organization.Connections(ctx, "org_test")
		assertStatus(t, err, http.StatusNotFound)
		assertOrgPresent(t, "after Connections")
	})

	t.Run("DeleteEnabledConnection", func(t *testing.T) {
		err := m.Organization.DeleteConnection(ctx, "org_test", "con_sms")
		assertStatus(t, err, http.StatusNotFound)
		assertOrgPresent(t, "after DeleteConnection")
	})

	t.Run("DeepUnknownSubpath", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v2/organizations/org_test/not/a/real/route", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("DELETE unknown subpath: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 for unknown subpath, got %d", resp.StatusCode)
		}
		assertOrgPresent(t, "after unknown subpath DELETE")
	})
}

// TestImplementedOrgRoutesStillDispatch guards against the router's segment
// matching being too strict and breaking the routes that do exist.
func TestImplementedOrgRoutesStillDispatch(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	t.Run("ReadOrganization", func(t *testing.T) {
		org, err := m.Organization.Read(ctx, "org_test")
		if err != nil {
			t.Fatalf("Organization.Read: %v", err)
		}
		if org.GetID() != "org_test" {
			t.Errorf("got %q", org.GetID())
		}
	})

	t.Run("ReadOrganizationByName", func(t *testing.T) {
		org, err := m.Organization.ReadByName(ctx, "test-org")
		if err != nil {
			t.Fatalf("Organization.ReadByName: %v", err)
		}
		if org.GetID() != "org_test" {
			t.Errorf("got %q", org.GetID())
		}
	})

	t.Run("ListMembers", func(t *testing.T) {
		members, err := m.Organization.Members(ctx, "org_test")
		if err != nil {
			t.Fatalf("Organization.Members: %v", err)
		}
		if len(members.Members) == 0 {
			t.Error("expected seeded members")
		}
	})

	t.Run("AssignMemberRoles", func(t *testing.T) {
		err := m.Organization.AssignMemberRoles(ctx, "org_test", "test_user_1", []string{"admin"})
		if err != nil {
			t.Fatalf("Organization.AssignMemberRoles: %v", err)
		}
	})

	t.Run("DeleteOrganizationStillWorks", func(t *testing.T) {
		name := "router-delete-org"
		org := &management.Organization{Name: &name}
		if err := m.Organization.Create(ctx, org); err != nil {
			t.Fatalf("Organization.Create: %v", err)
		}
		if err := m.Organization.Delete(ctx, org.GetID()); err != nil {
			t.Fatalf("Organization.Delete: %v", err)
		}
		_, err := m.Organization.Read(ctx, org.GetID())
		assertStatus(t, err, http.StatusNotFound)
	})
}

// assertStatus requires err to be a management.Error carrying want.
func assertStatus(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error with status %d, got nil", want)
	}
	var mErr management.Error
	if !errors.As(err, &mErr) {
		t.Fatalf("expected management.Error, got %T: %v", err, err)
	}
	if mErr.Status() != want {
		t.Fatalf("expected status %d, got %d: %v", want, mErr.Status(), err)
	}
}
