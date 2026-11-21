package server

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/auth0/go-auth0/management"
	"github.com/golang-jwt/jwt/v5"

	"github.com/46labs/auth0/pkg/config"
)

func roleNames(roles []*management.Role) []string {
	out := []string{}
	for _, r := range roles {
		out = append(out, r.GetName())
	}
	return out
}

func roleUserIDs(users []*management.User) []string {
	out := []string{}
	for _, u := range users {
		out = append(out, u.GetID())
	}
	return out
}

// Tenant role membership through the official SDK, from both sides, with the
// statuses Auth0 records (TestUserManager_Roles, TestRoleManager_Users).
func TestSDKUserRoles(t *testing.T) {
	_, m, _ := grantMgmt(t)
	ctx := context.Background()

	mod := &management.Role{Name: auth0String("pryr-moderator")}
	adm := &management.Role{Name: auth0String("pryr-admin")}
	for _, r := range []*management.Role{mod, adm} {
		if err := m.Role.Create(ctx, r); err != nil {
			t.Fatalf("Role.Create: %v", err)
		}
	}

	if err := m.User.AssignRoles(ctx, "test_user_1", []*management.Role{mod, adm}); err != nil {
		t.Fatalf("User.AssignRoles: %v", err)
	}
	// Assigning again changes nothing.
	if err := m.User.AssignRoles(ctx, "test_user_1", []*management.Role{mod}); err != nil {
		t.Fatalf("User.AssignRoles again: %v", err)
	}
	got, err := m.User.Roles(ctx, "test_user_1")
	if err != nil {
		t.Fatalf("User.Roles: %v", err)
	}
	if names := roleNames(got.Roles); !slices.Equal(names, []string{"pryr-admin", "pryr-moderator"}) || got.Total != 2 {
		t.Fatalf("User.Roles = %v (total %d)", names, got.Total)
	}

	if err := m.Role.AssignUsers(ctx, mod.GetID(), []*management.User{{ID: auth0String("test_user_2")}}); err != nil {
		t.Fatalf("Role.AssignUsers: %v", err)
	}
	users, err := m.Role.Users(ctx, mod.GetID())
	if err != nil {
		t.Fatalf("Role.Users: %v", err)
	}
	if ids := roleUserIDs(users.Users); !slices.Equal(ids, []string{"test_user_1", "test_user_2"}) {
		t.Fatalf("Role.Users = %v", ids)
	}

	if err := m.User.RemoveRoles(ctx, "test_user_1", []*management.Role{mod}); err != nil {
		t.Fatalf("User.RemoveRoles: %v", err)
	}
	users, err = m.Role.Users(ctx, mod.GetID())
	if err != nil {
		t.Fatalf("Role.Users: %v", err)
	}
	if ids := roleUserIDs(users.Users); !slices.Equal(ids, []string{"test_user_2"}) {
		t.Fatalf("after remove, Role.Users = %v", ids)
	}

	// A deleted role leaves no one holding it.
	if err := m.Role.Delete(ctx, adm.GetID()); err != nil {
		t.Fatalf("Role.Delete: %v", err)
	}
	got, err = m.User.Roles(ctx, "test_user_1")
	if err != nil {
		t.Fatalf("User.Roles: %v", err)
	}
	if len(got.Roles) != 0 {
		t.Fatalf("roles after delete = %v", roleNames(got.Roles))
	}

	// A deleted user leaves no membership behind.
	if err := m.User.Delete(ctx, "test_user_2"); err != nil {
		t.Fatalf("User.Delete: %v", err)
	}
	users, err = m.Role.Users(ctx, mod.GetID())
	if err != nil {
		t.Fatalf("Role.Users: %v", err)
	}
	if len(users.Users) != 0 {
		t.Fatalf("users after delete = %v", roleUserIDs(users.Users))
	}
}

func TestSDKUserRolesRefusals(t *testing.T) {
	_, m, _ := grantMgmt(t)
	ctx := context.Background()
	role := &management.Role{Name: auth0String("pryr-moderator")}
	if err := m.Role.Create(ctx, role); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}

	tests := []struct {
		name string
		call func() error
		want int
	}{
		{"assign to an unknown user", func() error { return m.User.AssignRoles(ctx, "nobody", []*management.Role{role}) }, http.StatusNotFound},
		{"assign an unknown role", func() error {
			return m.User.AssignRoles(ctx, "test_user_1", []*management.Role{{ID: auth0String("rol_missing")}})
		}, http.StatusBadRequest},
		{"assign no roles", func() error { return m.User.AssignRoles(ctx, "test_user_1", nil) }, http.StatusBadRequest},
		{"list an unknown user's roles", func() error { _, err := m.User.Roles(ctx, "nobody"); return err }, http.StatusNotFound},
		{"list an unknown role's users", func() error { _, err := m.Role.Users(ctx, "rol_missing"); return err }, http.StatusNotFound},
		{"assign an unknown user to a role", func() error {
			return m.Role.AssignUsers(ctx, role.GetID(), []*management.User{{ID: auth0String("nobody")}})
		}, http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assertStatus(t, tt.call(), tt.want) })
	}
}

// Role.Users pages both ways Auth0 does: page/per_page with totals, and
// checkpoint take/from with next and no totals.
func TestSDKRoleUsersPaging(t *testing.T) {
	srv, m, _ := grantMgmt(t)
	ctx := context.Background()
	role := &management.Role{Name: auth0String("pryr-moderator")}
	if err := m.Role.Create(ctx, role); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	want := []string{"u_a", "u_b", "u_c", "u_d", "u_e"}
	srv.mu.Lock()
	for _, id := range want {
		srv.users[id] = &config.User{ID: id, Email: id + "@example.com"}
	}
	srv.mu.Unlock()
	var all []*management.User
	for _, id := range want {
		all = append(all, &management.User{ID: auth0String(id)})
	}
	if err := m.Role.AssignUsers(ctx, role.GetID(), all); err != nil {
		t.Fatalf("Role.AssignUsers: %v", err)
	}

	t.Run("page", func(t *testing.T) {
		var got []string
		for page := 0; ; page++ {
			list, err := m.Role.Users(ctx, role.GetID(), management.Page(page), management.PerPage(2))
			if err != nil {
				t.Fatalf("Role.Users page %d: %v", page, err)
			}
			got = append(got, roleUserIDs(list.Users)...)
			if !list.HasNext() {
				break
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("paged users = %v", got)
		}
	})

	t.Run("checkpoint", func(t *testing.T) {
		var got []string
		from := ""
		for {
			opts := []management.RequestOption{management.Take(2)}
			if from != "" {
				opts = append(opts, management.From(from))
			}
			list, err := m.Role.Users(ctx, role.GetID(), opts...)
			if err != nil {
				t.Fatalf("Role.Users from %q: %v", from, err)
			}
			got = append(got, roleUserIDs(list.Users)...)
			if !list.HasNext() {
				break
			}
			// Opaque, as Auth0's is: not a user id a caller could build.
			if slices.Contains(want, list.Next) {
				t.Fatalf("next = %q, a raw user id", list.Next)
			}
			from = list.Next
		}
		if !slices.Equal(got, want) {
			t.Fatalf("checkpoint users = %v", got)
		}
	})
}

// Users declared with roles in config hold them from startup; a name no role
// has fails startup.
func TestSeedUserRoles(t *testing.T) {
	roles := map[string]*config.Role{"rol_m": {ID: "rol_m", Name: "pryr-moderator"}}
	got, err := seedUserRoles([]config.User{{ID: "u1", Roles: []string{"pryr-moderator", "pryr-moderator"}}, {ID: "u2"}}, roles)
	if err != nil {
		t.Fatalf("seedUserRoles: %v", err)
	}
	if !slices.Equal(got["u1"], []string{"rol_m"}) || len(got["u2"]) != 0 {
		t.Fatalf("seeded = %v", got)
	}
	if _, err := seedUserRoles([]config.User{{ID: "u1", Roles: []string{"pryr-admin"}}}, roles); err == nil {
		t.Fatal("an unknown role name seeded without error")
	}
}

// event.authorization.roles carries the user's tenant role names, so an
// Action can map them to a claim.
func TestActions_AuthorizationRoles(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("tenant-roles", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/roles", event.authorization.roles.join(","));
		};`)

	st, tok := login(t, ts, "")
	if st != 200 {
		t.Fatalf("token: %d %v", st, tok)
	}
	if got := claims(t, tok["access_token"])["https://mock/roles"]; got != "" {
		t.Fatalf("roles before assignment = %q", got)
	}

	srv.mu.Lock()
	srv.roles["rol_m"] = &config.Role{ID: "rol_m", Name: "pryr-moderator"}
	srv.roles["rol_a"] = &config.Role{ID: "rol_a", Name: "pryr-admin"}
	srv.userRoles["test_user_1"] = []string{"rol_m", "rol_a"}
	srv.mu.Unlock()

	st, tok = login(t, ts, "")
	if st != 200 {
		t.Fatalf("token: %d %v", st, tok)
	}
	if got := claims(t, tok["access_token"])["https://mock/roles"]; got != "pryr-admin,pryr-moderator" {
		t.Fatalf("roles = %q", got)
	}
}

// A client credentials token carries its grant's scopes, narrowed to those
// requested; a scope the grant lacks is refused. A client with no grant for

// Every way a user goes away takes their roles with them: linking into
// another account and deleting their connection, besides deleting the user.
func TestRolesLeaveWithTheUser(t *testing.T) {
	srv, m, _ := grantMgmt(t)
	ctx := context.Background()
	role := &management.Role{Name: auth0String("pryr-moderator")}
	if err := m.Role.Create(ctx, role); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	conn := &management.Connection{Name: auth0String("email-other"), Strategy: auth0String("email")}
	if err := m.Connection.Create(ctx, conn); err != nil {
		t.Fatalf("Connection.Create: %v", err)
	}
	srv.mu.Lock()
	srv.users["email|linked"] = &config.User{ID: "email|linked", Identities: []config.UserIdentity{{Provider: "email", UserID: "linked", Connection: "email"}}}
	srv.users["email|orphan"] = &config.User{ID: "email|orphan", Identities: []config.UserIdentity{{Provider: "email", UserID: "orphan", Connection: "email-other"}}}
	srv.mu.Unlock()
	if err := m.Role.AssignUsers(ctx, role.GetID(), []*management.User{{ID: auth0String("email|linked")}, {ID: auth0String("email|orphan")}}); err != nil {
		t.Fatalf("Role.AssignUsers: %v", err)
	}

	if st, msg, _ := srv.linkUser("test_user_1", "email", "linked", ""); st != http.StatusCreated {
		t.Fatalf("link: %d %s", st, msg)
	}
	if err := m.Connection.Delete(ctx, conn.GetID()); err != nil {
		t.Fatalf("Connection.Delete: %v", err)
	}
	users, err := m.Role.Users(ctx, role.GetID())
	if err != nil {
		t.Fatalf("Role.Users: %v", err)
	}
	if len(users.Users) != 0 {
		t.Fatalf("role users after link and connection delete = %v", roleUserIDs(users.Users))
	}
}

// The wire shapes Auth0's OpenAPI document gives these endpoints. Raw JSON
// because the SDK's typed decode hides envelope fields it does not model.
func TestRoleMembershipWireShapes(t *testing.T) {
	_, m, _ := grantMgmt(t)
	ctx := context.Background()
	role := &management.Role{Name: auth0String("pryr-moderator")}
	if err := m.Role.Create(ctx, role); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	if err := m.User.AssignRoles(ctx, "test_user_1", []*management.Role{role}); err != nil {
		t.Fatalf("User.AssignRoles: %v", err)
	}

	keys := func(uri string) []string {
		var body map[string]any
		if err := m.Request(ctx, http.MethodGet, uri, &body); err != nil {
			t.Fatalf("GET %s: %v", uri, err)
		}
		out := []string{}
		for k := range body {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	for _, tt := range []struct{ uri, want string }{
		{m.URI("users", "test_user_1", "roles") + "?include_totals=true", "limit roles start total"},
		{m.URI("roles", role.GetID(), "users") + "?include_totals=true", "limit start total users"},
		{m.URI("roles", role.GetID(), "users") + "?take=1", "users"},
	} {
		if got := strings.Join(keys(tt.uri), " "); got != tt.want {
			t.Errorf("%s keys = %q, want %q", tt.uri, got, tt.want)
		}
	}

	// users is required but may be empty; unknown fields are refused.
	if err := m.Request(ctx, http.MethodPost, m.URI("roles", role.GetID(), "users"), &map[string]any{"users": []string{}}); err != nil {
		t.Errorf("empty users: %v", err)
	}
	for _, tt := range []struct {
		name, uri string
		body      map[string]any
	}{
		{"users missing", m.URI("roles", role.GetID(), "users"), map[string]any{}},
		{"extra field on role users", m.URI("roles", role.GetID(), "users"), map[string]any{"users": []string{}, "extra": 1}},
		{"extra field on user roles", m.URI("users", "test_user_1", "roles"), map[string]any{"roles": []string{role.GetID()}, "extra": 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertStatus(t, m.Request(ctx, http.MethodPost, tt.uri, &tt.body), http.StatusBadRequest)
		})
	}
}

// Paging values outside the OpenAPI document's bounds are refused, not
// clamped, on the endpoints this mock added.
func TestRoleMembershipRefusesBadPaging(t *testing.T) {
	_, m, _ := grantMgmt(t)
	ctx := context.Background()
	role := &management.Role{Name: auth0String("pryr-moderator")}
	if err := m.Role.Create(ctx, role); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	for _, tt := range []struct{ name, key, value string }{
		{"negative page", "page", "-1"},
		{"page not a number", "page", "x"},
		{"per_page zero", "per_page", "0"},
		{"per_page over 100", "per_page", "101"},
		{"take over 100", "take", "101"},
		{"include_totals not a boolean", "include_totals", "yes"},
		{"from not a checkpoint", "from", "%%%"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.Role.Users(ctx, role.GetID(), management.Parameter(tt.key, tt.value))
			assertStatus(t, err, http.StatusBadRequest)
		})
	}
	_, err := m.User.Roles(ctx, "test_user_1", management.PerPage(101))
	assertStatus(t, err, http.StatusBadRequest)
}

// A declarative ${authorization.roles} resolves to nothing for a user with no
// tenant roles, as before this mock had them, so no claim appears.
func TestDeclarativeAuthorizationRolesUnchangedWithoutRoles(t *testing.T) {
	srv := minimalServer(t, &config.PostLoginAction{
		AccessTokenRawClaims: map[string]string{"roles": "${authorization.roles}"},
	})
	access := jwt.MapClaims{}
	srv.applyPostLogin(srv.users["auth0|u1"], srv.clients["spa_app"], "", jwt.MapClaims{}, access)
	if v, has := access["roles"]; has {
		t.Fatalf("roles claim = %v, want none", v)
	}
}

// A body is one JSON object; anything after it is refused.
func TestRoleMembershipRefusesTrailingJSON(t *testing.T) {
	_, m, ts := grantMgmt(t)
	role := &management.Role{Name: auth0String("pryr-moderator")}
	if err := m.Role.Create(context.Background(), role); err != nil {
		t.Fatalf("Role.Create: %v", err)
	}
	for path, body := range map[string]string{
		"/api/v2/users/test_user_1/roles":          `{"roles":["` + role.GetID() + `"]} {}`,
		"/api/v2/roles/" + role.GetID() + "/users": `{"users":["test_user_1"]} {}`,
	} {
		// Raw HTTP: the SDK cannot send a body with trailing data.
		resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST %s with trailing JSON = %d, want 400", path, resp.StatusCode)
		}
	}
}

// A user whose id is "roles" is still served by the user route.
func TestUserNamedRolesIsAUser(t *testing.T) {
	srv, m, _ := grantMgmt(t)
	srv.mu.Lock()
	srv.users["roles"] = &config.User{ID: "roles", Email: "roles@example.com"}
	srv.mu.Unlock()
	u, err := m.User.Read(context.Background(), "roles")
	if err != nil || u.GetEmail() != "roles@example.com" {
		t.Fatalf("User.Read(roles) = %v, %v", u, err)
	}
}
