package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/auth0/go-auth0/management"
)

// TestSDKRoles drives the roles collection through the official SDK. pee
// resolves its admin carrier role at runtime with read-or-create by name, so
// name_filter and the duplicate conflict are the load-bearing parts.
func TestSDKRoles(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	t.Run("EmptyRegistry", func(t *testing.T) {
		list, err := m.Role.List(ctx)
		if err != nil {
			t.Fatalf("Role.List: %v", err)
		}
		if len(list.Roles) != 0 {
			t.Errorf("expected no roles, got %d", len(list.Roles))
		}
	})

	t.Run("Create", func(t *testing.T) {
		for _, name := range []string{"superadmin", "admin", "user"} {
			role := &management.Role{
				Name:        auth0String(name),
				Description: auth0String(name + " role"),
			}
			if err := m.Role.Create(ctx, role); err != nil {
				t.Fatalf("Role.Create(%s): %v", name, err)
			}
			if role.GetID() == "" {
				t.Errorf("no id generated for %s", name)
			}
			if role.GetName() != name {
				t.Errorf("name = %q, want %q", role.GetName(), name)
			}
		}
	})

	t.Run("DuplicateNameConflicts", func(t *testing.T) {
		err := m.Role.Create(ctx, &management.Role{Name: auth0String("admin")})
		assertStatus(t, err, http.StatusConflict)
	})

	t.Run("DuplicateNameIsCaseInsensitive", func(t *testing.T) {
		err := m.Role.Create(ctx, &management.Role{Name: auth0String("ADMIN")})
		assertStatus(t, err, http.StatusConflict)
	})

	t.Run("CreateRequiresName", func(t *testing.T) {
		err := m.Role.Create(ctx, &management.Role{Description: auth0String("nameless")})
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("ListAll", func(t *testing.T) {
		list, err := m.Role.List(ctx)
		if err != nil {
			t.Fatalf("Role.List: %v", err)
		}
		if len(list.Roles) != 3 {
			t.Fatalf("expected 3 roles, got %d", len(list.Roles))
		}
	})

	// This is the read half of read-or-create by name.
	t.Run("NameFilter", func(t *testing.T) {
		list, err := m.Role.List(ctx, management.Parameter("name_filter", "admin"))
		if err != nil {
			t.Fatalf("Role.List: %v", err)
		}
		// Substring match, so "admin" also matches "superadmin".
		names := map[string]bool{}
		for _, role := range list.Roles {
			names[role.GetName()] = true
		}
		if !names["admin"] || !names["superadmin"] {
			t.Errorf("name_filter=admin should match admin and superadmin, got %+v", names)
		}
		if names["user"] {
			t.Error("name_filter=admin should not match user")
		}
	})

	t.Run("NameFilterNoMatch", func(t *testing.T) {
		list, err := m.Role.List(ctx, management.Parameter("name_filter", "nonesuch"))
		if err != nil {
			t.Fatalf("Role.List: %v", err)
		}
		if len(list.Roles) != 0 {
			t.Errorf("expected no matches, got %d", len(list.Roles))
		}
	})

	t.Run("ReadUpdateDelete", func(t *testing.T) {
		role := &management.Role{Name: auth0String("temporary")}
		if err := m.Role.Create(ctx, role); err != nil {
			t.Fatalf("Role.Create: %v", err)
		}

		read, err := m.Role.Read(ctx, role.GetID())
		if err != nil {
			t.Fatalf("Role.Read: %v", err)
		}
		if read.GetName() != "temporary" {
			t.Errorf("name = %q", read.GetName())
		}

		if err := m.Role.Update(ctx, role.GetID(),
			&management.Role{Description: auth0String("updated")}); err != nil {
			t.Fatalf("Role.Update: %v", err)
		}
		read2, err := m.Role.Read(ctx, role.GetID())
		if err != nil {
			t.Fatalf("Role.Read: %v", err)
		}
		if read2.GetDescription() != "updated" {
			t.Errorf("description = %q, want updated", read2.GetDescription())
		}
		if read2.GetName() != "temporary" {
			t.Errorf("an omitted name was changed: %q", read2.GetName())
		}

		if err := m.Role.Delete(ctx, role.GetID()); err != nil {
			t.Fatalf("Role.Delete: %v", err)
		}
		_, err = m.Role.Read(ctx, role.GetID())
		assertStatus(t, err, http.StatusNotFound)
	})

	t.Run("ReadUnknown", func(t *testing.T) {
		_, err := m.Role.Read(ctx, "rol_nope")
		assertStatus(t, err, http.StatusNotFound)
	})
}

// TestInvitationRejectsUnknownRoleID keeps an invitation from carrying a grant
// that resolves to nothing on acceptance.
func TestInvitationRejectsUnknownRoleID(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inv := f.invitation("badrole@example.test")
	inv.Roles = []string{"rol_does_not_exist"}
	err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
	assertStatus(t, err, http.StatusBadRequest)

	t.Run("KnownRoleAccepted", func(t *testing.T) {
		ok := f.invitation("goodrole@example.test")
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, ok); err != nil {
			t.Fatalf("CreateInvitation with a known role id: %v", err)
		}
	})

	t.Run("NoRolesAccepted", func(t *testing.T) {
		none := f.invitation("norole@example.test")
		none.Roles = nil
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, none); err != nil {
			t.Fatalf("CreateInvitation with no roles: %v", err)
		}
	})
}

// TestMemberRolesCarryRegistryID checks the members response pairs the stored
// role name with the registry's id, rather than echoing the name as both.
func TestMemberRolesCarryRegistryID(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	const email = "member-roles@example.test"
	inv := f.createInvitation(t, email)
	if tokens, status, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID); tokens == nil {
		t.Fatalf("acceptance failed with %d: %s", status, msg)
	}

	members, err := f.m.Organization.Members(ctx, f.orgID)
	if err != nil {
		t.Fatalf("Organization.Members: %v", err)
	}

	user := f.srv.findUser(email)
	if user == nil {
		t.Fatal("invitee not created")
	}

	for _, member := range members.Members {
		if member.GetUserID() != user.ID {
			continue
		}
		if len(member.Roles) != 1 {
			t.Fatalf("expected one role, got %+v", member.Roles)
		}
		if got := member.Roles[0].GetName(); got != "admin" {
			t.Errorf("role name = %q, want admin", got)
		}
		if got := member.Roles[0].GetID(); got != f.adminRoleID {
			t.Errorf("role id = %q, want the registry id %q", got, f.adminRoleID)
		}
		return
	}
	t.Fatal("the invitee is not listed as a member")
}

// TestRoleIDsAreServerGenerated keeps a caller-supplied id from overwriting an
// existing role and slipping past the duplicate-name conflict.
func TestRoleIDsAreServerGenerated(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	first := &management.Role{Name: auth0String("admin")}
	if err := m.Role.Create(ctx, first); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	// By value: Create decodes the response through the pointer it was given,
	// so sharing first.ID below would mutate this too.
	firstID := first.GetID()

	// Same id, different name: must not land on top of the existing role.
	hijack := &management.Role{ID: auth0String(firstID), Name: auth0String("hijacked")}
	if err := m.Role.Create(ctx, hijack); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	if hijack.GetID() == firstID {
		t.Error("a caller-supplied id was honored")
	}

	read, err := m.Role.Read(ctx, firstID)
	if err != nil {
		t.Fatalf("Role.Read: %v", err)
	}
	if read.GetName() != "admin" {
		t.Errorf("the original role was overwritten: name = %q", read.GetName())
	}
}

// TestRoleLifecycleKeepsMembersConsistent covers rename and delete: members
// store the role name, so both have to follow through or assignments go stale.
func TestRoleLifecycleKeepsMembersConsistent(t *testing.T) {
	memberRole := func(t *testing.T, f *inviteFixture, userID string) string {
		t.Helper()
		for _, m := range f.srv.GetOrgMembers(f.orgID) {
			if m.UserID == userID {
				return m.Role
			}
		}
		return "<not a member>"
	}

	t.Run("Rename", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()
		ctx := context.Background()

		const email = "renamed@example.test"
		inv := f.createInvitation(t, email)
		if tokens, st, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID); tokens == nil {
			t.Fatalf("acceptance failed with %d: %s", st, msg)
		}
		user := f.srv.findUser(email)

		if err := f.m.Role.Update(ctx, f.adminRoleID,
			&management.Role{Name: auth0String("tenant-admin")}); err != nil {
			t.Fatalf("Role.Update: %v", err)
		}
		if got := memberRole(t, f, user.ID); got != "tenant-admin" {
			t.Errorf("member role = %q, want it renamed to tenant-admin", got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()
		ctx := context.Background()

		const email = "deleted-role@example.test"
		inv := f.createInvitation(t, email)
		if tokens, st, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID); tokens == nil {
			t.Fatalf("acceptance failed with %d: %s", st, msg)
		}
		user := f.srv.findUser(email)

		if err := f.m.Role.Delete(ctx, f.adminRoleID); err != nil {
			t.Fatalf("Role.Delete: %v", err)
		}
		if got := memberRole(t, f, user.ID); got != "" {
			t.Errorf("member role = %q, want it cleared with the role", got)
		}
	})

	t.Run("DeletedBetweenInviteAndAcceptance", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()
		ctx := context.Background()

		const email = "vanished@example.test"
		inv := f.createInvitation(t, email)
		if err := f.m.Role.Delete(ctx, f.adminRoleID); err != nil {
			t.Fatalf("Role.Delete: %v", err)
		}

		// Redemption must fail rather than quietly grant nothing.
		tokens, _, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID)
		if tokens != nil {
			t.Fatal("an invitation whose role was deleted was accepted")
		}
		if !strings.Contains(msg, "no longer exists") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})
}

// TestMultipleRolesAreRefused pins that the single-role limitation is stated
// rather than applied by silently dropping the rest.
func TestMultipleRolesAreRefused(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	second := &management.Role{Name: auth0String("superadmin")}
	if err := f.m.Role.Create(ctx, second); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}

	t.Run("Invitation", func(t *testing.T) {
		inv := f.invitation("multirole@example.test")
		inv.Roles = []string{f.adminRoleID, second.GetID()}
		err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv)
		assertStatus(t, err, http.StatusBadRequest)
	})

	t.Run("MemberRoles", func(t *testing.T) {
		err := f.m.Organization.AssignMemberRoles(ctx, f.orgID, "test_user_1",
			[]string{f.adminRoleID, second.GetID()})
		assertStatus(t, err, http.StatusBadRequest)
	})
}

// TestListsHonourIncludeTotals covers the envelope-versus-array contract:
// Auth0 returns a bare array unless include_totals=true, which is what
// go-auth0 always sends.
func TestListsHonourIncludeTotals(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	for _, path := range []string{
		"/api/v2/organizations",
		"/api/v2/connections",
		"/api/v2/clients",
		"/api/v2/roles",
		"/api/v2/organizations/org_test/members",
	} {
		t.Run(path, func(t *testing.T) {
			bare := decodeAny(t, ts.URL+path)
			if _, isObject := bare.(map[string]any); isObject {
				t.Errorf("without include_totals the body should be a bare array, got an object")
			}

			withTotals := decodeAny(t, ts.URL+path+"?include_totals=true")
			obj, isObject := withTotals.(map[string]any)
			if !isObject {
				t.Fatalf("with include_totals=true the body should be an object, got %T", withTotals)
			}
			for _, key := range []string{"start", "limit", "total"} {
				if _, ok := obj[key]; !ok {
					t.Errorf("envelope missing %q: %v", key, obj)
				}
			}
		})
	}
}

func decodeAny(t *testing.T, url string) any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", url, resp.StatusCode)
	}
	var out any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return out
}

// TestUnimplementedRoleSubresourceDoesNotDeleteRole is the phase-1 hazard
// again, in the roles router: truncating the path at the slash dispatched
// DELETE .../roles/{id}/permissions to deleteRole and destroyed the role while
// answering success.
func TestUnimplementedRoleSubresourceDoesNotDeleteRole(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	role := &management.Role{Name: auth0String("survivor")}
	if err := m.Role.Create(ctx, role); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	roleID := role.GetID()

	t.Run("RemovePermissions", func(t *testing.T) {
		err := m.Role.RemovePermissions(ctx, roleID, []*management.Permission{
			{Name: auth0String("p"), ResourceServerIdentifier: auth0String("api")},
		})
		assertStatus(t, err, http.StatusNotFound)

		if _, err := m.Role.Read(ctx, roleID); err != nil {
			t.Fatalf("the role was destroyed by a permissions subpath: %v", err)
		}
	})

	t.Run("ReadPermissions", func(t *testing.T) {
		_, err := m.Role.Permissions(ctx, roleID)
		assertStatus(t, err, http.StatusNotFound)
		if _, err := m.Role.Read(ctx, roleID); err != nil {
			t.Fatalf("the role went missing: %v", err)
		}
	})

	t.Run("Users", func(t *testing.T) {
		_, err := m.Role.Users(ctx, roleID)
		assertStatus(t, err, http.StatusNotFound)
		if _, err := m.Role.Read(ctx, roleID); err != nil {
			t.Fatalf("the role went missing: %v", err)
		}
	})

	t.Run("DeleteStillWorksOnTheExactPath", func(t *testing.T) {
		if err := m.Role.Delete(ctx, roleID); err != nil {
			t.Fatalf("Role.Delete: %v", err)
		}
		_, err := m.Role.Read(ctx, roleID)
		assertStatus(t, err, http.StatusNotFound)
	})
}

// TestFailedRedemptionLeavesNoUser covers the ordering: the role has to
// resolve before find-or-create, or a refused acceptance strands an account.
func TestFailedRedemptionLeavesNoUser(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	const email = "never-created@example.test"
	inv := f.createInvitation(t, email)
	if err := f.m.Role.Delete(ctx, f.adminRoleID); err != nil {
		t.Fatalf("Role.Delete: %v", err)
	}

	if tokens, _, _ := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID); tokens != nil {
		t.Fatal("acceptance succeeded despite the role being gone")
	}

	if user := f.srv.findUser(email); user != nil {
		t.Errorf("a failed redemption left an orphaned account: %s", user.ID)
	}
}

// TestOrgRolesNotSeededWithoutOrganization covers the Action's non-org guard:
// a login carrying no organization must not write org_roles at all.
func TestOrgRolesNotSeededWithoutOrganization(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	// A login with no `organization` parameter. test_user_1's app_metadata
	// carries tenant_id, so org_id still resolves from it, but nothing should
	// be seeded for an empty organization.
	before := f.srv.getUserByID("test_user_1")
	if before.AppMetadata.OrgRole("") != "" {
		t.Fatal("fixture already has an empty-key org_roles entry")
	}

	code := f.srv.IssueAuthCode("test_user_1", "openid", "", "test_client")
	if code == "" {
		t.Fatal("no code issued")
	}

	after := f.srv.seedOrgRoles("test_user_1", "")
	if after == nil {
		t.Fatal("seedOrgRoles returned nil for a known user")
	}
	if _, present := after.AppMetadata["org_roles"]; present {
		t.Errorf("org_roles was written for a login with no organization: %#v", after.AppMetadata)
	}
}

// statusRecorder captures the status of each response the SDK receives, so a
// status can be asserted while the request and its decoding still go through
// the official client.
type statusRecorder struct {
	mu       sync.Mutex
	statuses map[string]int
	next     http.RoundTripper
}

func (r *statusRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if resp != nil {
		r.mu.Lock()
		r.statuses[req.Method+" "+resp.Request.URL.Path] = resp.StatusCode
		r.mu.Unlock()
	}
	return resp, err
}

func (r *statusRecorder) status(t *testing.T, method, path string) int {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	code, ok := r.statuses[method+" "+path]
	if !ok {
		t.Fatalf("no response recorded for %s %s (recorded: %v)", method, path, r.statuses)
	}
	return code
}

// sdkWithStatuses builds a Management client whose responses are recorded.
func sdkWithStatuses(t *testing.T, baseURL string) (*management.Management, *statusRecorder) {
	t.Helper()

	rec := &statusRecorder{statuses: map[string]int{}, next: http.DefaultTransport}
	m, err := management.New(baseURL,
		management.WithStaticToken("mock_token"),
		management.WithInsecure(),
		management.WithClient(&http.Client{Transport: rec}),
	)
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	return m, rec
}

// TestManagementStatusCodes pins the success codes against the SDK's recorded
// traffic (test/data/recordings/*.yaml). Auth0 is not uniform: role writes
// answer 200, most creates 201, member-role writes 204. The docs site
// disagrees with the recordings on invitations, so the recordings win.
//
// Driven through the SDK with a recording transport, so the assertion covers
// what a real consumer sends and decodes, not just what the mock returns.
func TestManagementStatusCodes(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	m, rec := sdkWithStatuses(t, f.ts.URL)
	ctx := context.Background()

	role := &management.Role{Name: auth0String("pinned")}
	if err := m.Role.Create(ctx, role); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	if got := rec.status(t, http.MethodPost, "/api/v2/roles"); got != http.StatusOK {
		t.Errorf("POST /roles = %d, want 200", got)
	}

	org := &management.Organization{Name: auth0String("pinned-org")}
	if err := m.Organization.Create(ctx, org); err != nil {
		t.Fatalf("Organization.Create: %v", err)
	}
	if got := rec.status(t, http.MethodPost, "/api/v2/organizations"); got != http.StatusCreated {
		t.Errorf("POST /organizations = %d, want 201", got)
	}

	client := &management.Client{Name: auth0String("Pinned")}
	if err := m.Client.Create(ctx, client); err != nil {
		t.Fatalf("Client.Create: %v", err)
	}
	if got := rec.status(t, http.MethodPost, "/api/v2/clients"); got != http.StatusCreated {
		t.Errorf("POST /clients = %d, want 201", got)
	}

	inv := f.invitation("pin@example.test")
	if err := m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	invPath := "/api/v2/organizations/" + f.orgID + "/invitations"
	if got := rec.status(t, http.MethodPost, invPath); got != http.StatusCreated {
		t.Errorf("POST %s = %d, want 201 (the docs site says 200; the recordings say 201)", invPath, got)
	}

	if err := m.Organization.AssignMemberRoles(ctx, f.orgID, "test_user_1", []string{f.adminRoleID}); err != nil {
		t.Fatalf("AssignMemberRoles: %v", err)
	}
	rolesPath := "/api/v2/organizations/" + f.orgID + "/members/test_user_1/roles"
	if got := rec.status(t, http.MethodPost, rolesPath); got != http.StatusNoContent {
		t.Errorf("POST %s = %d, want 204", rolesPath, got)
	}

	if err := m.Role.Delete(ctx, role.GetID()); err != nil {
		t.Fatalf("Role.Delete: %v", err)
	}
	if got := rec.status(t, http.MethodDelete, "/api/v2/roles/"+role.GetID()); got != http.StatusOK {
		t.Errorf("DELETE /roles/{id} = %d, want 200", got)
	}
}

// TestInvitationRolesMinItems covers the schema's minItems 1: an omitted
// roles field is fine, an explicit empty array is not.
//
// The SDK tags Roles omitempty, so its typed method cannot express an empty
// array at all — the explicit case goes through Management.Request, which
// still uses the SDK's transport and error decoding.
func TestInvitationRolesMinItems(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	m, _ := sdkWithStatuses(t, f.ts.URL)
	ctx := context.Background()

	omitted := f.invitation("omitted@example.test")
	omitted.Roles = nil
	if err := m.Organization.CreateInvitation(ctx, f.orgID, omitted); err != nil {
		t.Fatalf("an omitted roles field should be accepted: %v", err)
	}

	payload := map[string]any{
		"inviter":   map[string]string{"name": "A"},
		"invitee":   map[string]string{"email": "empty@example.test"},
		"client_id": f.clientID,
		"roles":     []string{},
	}
	err := m.Request(ctx, http.MethodPost,
		m.URI("organizations", f.orgID, "invitations"), payload)
	assertStatus(t, err, http.StatusBadRequest)
}
