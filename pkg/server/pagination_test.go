package server

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/auth0/go-auth0/management"
)

// TestInvitationListPaginationTerminates is the regression the review caught:
// the SDK's own documentation for organization invitations tells callers to
// page until they get an empty result, because HasNext cannot be used there.
// A handler that ignores page/per_page serves page 0 forever and that loop
// never ends.
func TestInvitationListPaginationTerminates(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	const total = 7
	for i := range total {
		email := string(rune('a'+i)) + "@example.test"
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, f.invitation(email)); err != nil {
			t.Fatalf("CreateInvitation(%s): %v", email, err)
		}
	}

	seen := map[string]bool{}
	pages := 0
	for page := 0; ; page++ {
		// Guard so a broken handler fails the test instead of hanging it.
		if page > 20 {
			t.Fatal("pagination never returned an empty page")
		}
		list, err := f.m.Organization.Invitations(ctx, f.orgID,
			management.Page(page), management.PerPage(3))
		if err != nil {
			t.Fatalf("Invitations(page=%d): %v", page, err)
		}
		if len(list.OrganizationInvitations) == 0 {
			break
		}
		pages++
		for _, inv := range list.OrganizationInvitations {
			email := inv.GetInvitee().GetEmail()
			if seen[email] {
				t.Errorf("invitation for %s repeated across pages", email)
			}
			seen[email] = true
		}
	}

	if len(seen) != total {
		t.Errorf("paged over %d unique invitations, want %d", len(seen), total)
	}
	// 7 items at 3 per page.
	if pages != 3 {
		t.Errorf("walked %d non-empty pages, want 3", pages)
	}
}

// TestInvitationListEnvelope pins the values management.List decodes, since
// HasNext is computed from them.
func TestInvitationListEnvelope(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	for i := range 5 {
		email := string(rune('a'+i)) + "@envelope.test"
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, f.invitation(email)); err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
	}

	first, err := f.m.Organization.Invitations(ctx, f.orgID,
		management.Page(0), management.PerPage(2))
	if err != nil {
		t.Fatalf("Invitations: %v", err)
	}
	if first.Start != 0 || first.Limit != 2 || first.Total != 5 || first.Length != 2 {
		t.Errorf("first page envelope = start:%d limit:%d length:%d total:%d, want 0/2/2/5",
			first.Start, first.Limit, first.Length, first.Total)
	}
	if !first.HasNext() {
		t.Error("HasNext should be true on the first of three pages")
	}

	last, err := f.m.Organization.Invitations(ctx, f.orgID,
		management.Page(2), management.PerPage(2))
	if err != nil {
		t.Fatalf("Invitations: %v", err)
	}
	if last.Start != 4 || last.Length != 1 {
		t.Errorf("last page envelope = start:%d length:%d, want 4/1", last.Start, last.Length)
	}
	if last.HasNext() {
		t.Error("HasNext should be false on the last page")
	}
}

// TestListPaginationAppliesToEveryCollection covers the other list endpoints,
// which had the same page-0-forever behavior.
func TestListPaginationAppliesToEveryCollection(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	for i := range 4 {
		name := "page-org-" + string(rune('a'+i))
		if err := m.Organization.Create(ctx, &management.Organization{Name: &name}); err != nil {
			t.Fatalf("Organization.Create: %v", err)
		}
	}

	t.Run("Organizations", func(t *testing.T) {
		first, err := m.Organization.List(ctx, management.Page(0), management.PerPage(2))
		if err != nil {
			t.Fatalf("Organization.List: %v", err)
		}
		if len(first.Organizations) != 2 {
			t.Fatalf("page 0 returned %d, want 2", len(first.Organizations))
		}
		second, err := m.Organization.List(ctx, management.Page(1), management.PerPage(2))
		if err != nil {
			t.Fatalf("Organization.List page 1: %v", err)
		}
		if len(second.Organizations) == 0 {
			t.Fatal("page 1 was empty")
		}
		if first.Organizations[0].GetID() == second.Organizations[0].GetID() {
			t.Error("page 1 repeated page 0")
		}
	})

	t.Run("Connections", func(t *testing.T) {
		first, err := m.Connection.List(ctx, management.Page(0), management.PerPage(1))
		if err != nil {
			t.Fatalf("Connection.List: %v", err)
		}
		second, err := m.Connection.List(ctx, management.Page(1), management.PerPage(1))
		if err != nil {
			t.Fatalf("Connection.List page 1: %v", err)
		}
		if len(first.Connections) != 1 || len(second.Connections) != 1 {
			t.Fatalf("expected one connection per page, got %d and %d",
				len(first.Connections), len(second.Connections))
		}
		if first.Connections[0].GetID() == second.Connections[0].GetID() {
			t.Error("page 1 repeated page 0")
		}
	})

	t.Run("PageBeyondEndIsEmpty", func(t *testing.T) {
		out, err := m.Organization.List(ctx, management.Page(99), management.PerPage(10))
		if err != nil {
			t.Fatalf("Organization.List: %v", err)
		}
		if len(out.Organizations) != 0 {
			t.Errorf("page past the end returned %d organizations", len(out.Organizations))
		}
	})

	t.Run("DefaultsReturnEverything", func(t *testing.T) {
		out, err := m.Organization.List(ctx)
		if err != nil {
			t.Fatalf("Organization.List: %v", err)
		}
		if len(out.Organizations) != out.Total {
			t.Errorf("default page returned %d of %d", len(out.Organizations), out.Total)
		}
	})

	t.Run("EnabledConnections", func(t *testing.T) {
		first, err := m.Organization.Connections(ctx, "org_test",
			management.Page(0), management.PerPage(1))
		if err != nil {
			t.Fatalf("Organization.Connections: %v", err)
		}
		second, err := m.Organization.Connections(ctx, "org_test",
			management.Page(1), management.PerPage(1))
		if err != nil {
			t.Fatalf("Organization.Connections page 1: %v", err)
		}
		if len(first.OrganizationConnections) != 1 || len(second.OrganizationConnections) != 1 {
			t.Fatalf("expected one pairing per page, got %d and %d",
				len(first.OrganizationConnections), len(second.OrganizationConnections))
		}
		if first.OrganizationConnections[0].GetConnectionID() == second.OrganizationConnections[0].GetConnectionID() {
			t.Error("page 1 repeated page 0")
		}
	})
}

// TestPaginateHugePageDoesNotOverflow covers the crash path: page*perPage
// overflows int for a large page value, producing a negative lower bound that
// panics every handler slicing its collection with it.
func TestPaginateHugePageDoesNotOverflow(t *testing.T) {
	for _, page := range []string{
		strconv.Itoa(math.MaxInt),
		strconv.Itoa(math.MaxInt / 2),
		"9223372036854775807",
		"184467440737095516",
	} {
		t.Run("page="+page, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/?page="+page+"&per_page=50", nil)

			lo, hi, window := paginate(r, 7)

			if lo < 0 || hi < 0 {
				t.Fatalf("negative bounds lo=%d hi=%d would panic on slicing", lo, hi)
			}
			if lo > 7 || hi > 7 {
				t.Fatalf("bounds past the collection lo=%d hi=%d (len 7)", lo, hi)
			}
			if lo > hi {
				t.Fatalf("inverted bounds lo=%d hi=%d", lo, hi)
			}
			if window.Total != 7 {
				t.Errorf("total = %d, want 7", window.Total)
			}

			// And the bounds must actually be usable.
			items := make([]int, 7)
			if got := len(items[lo:hi]); got != 0 {
				t.Errorf("page past the end yielded %d items", got)
			}
		})
	}
}

// TestPaginateOverflowThroughAHandler proves the guard holds end to end, since
// a panic in a handler surfaces as a broken response rather than a Go panic in
// the test process.
func TestPaginateOverflowThroughAHandler(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	for _, path := range []string{
		"/api/v2/organizations?page=9223372036854775807",
		"/api/v2/connections?page=9223372036854775807&per_page=100",
		"/api/v2/clients?page=9223372036854775807",
		"/api/v2/organizations/org_test/members?page=9223372036854775807",
		"/api/v2/organizations/org_test/enabled_connections?page=9223372036854775807",
		"/api/v2/organizations/org_test/invitations?page=9223372036854775807",
		"/api/v2/users/test_user_1/organizations?page=9223372036854775807",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Errorf("GET %s: %v", path, err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: got %d, want 200", path, resp.StatusCode)
		}
	}
}
