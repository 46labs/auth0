package config

import (
	"encoding/json"
	"testing"
)

// TestAppMetadataCloneIsolatesNestedJSON covers the shape that matters most:
// app_metadata.org_roles is a nested map mutated in place by role writes, so a
// clone that shared it would let a reader observe a half-applied change.
func TestAppMetadataCloneIsolatesNestedJSON(t *testing.T) {
	src := AppMetadata{
		AppMetaTenantID: "org_a",
		AppMetaOrgRoles: map[string]any{
			"org_a": "admin",
			"org_b": "member",
		},
	}

	clone := src.Clone()

	// Mutating the clone's nested map must not reach the source.
	clone[AppMetaOrgRoles].(map[string]any)["org_a"] = "viewer"
	if got := src.OrgRole("org_a"); got != "admin" {
		t.Errorf("source org_roles[org_a] changed via clone: %q", got)
	}

	// And the reverse.
	src[AppMetaOrgRoles].(map[string]any)["org_b"] = "superadmin"
	if got := clone.OrgRole("org_b"); got != "member" {
		t.Errorf("clone org_roles[org_b] changed via source: %q", got)
	}
}

// TestCloneIsolatesConcreteCollectionTypes exercises the reflection path.
// mapstructure-decoded config and programmatically built metadata yield
// concrete types ([]string, map[string][]string) rather than the []any /
// map[string]any that encoding/json produces.
func TestCloneIsolatesConcreteCollectionTypes(t *testing.T) {
	src := AppMetadata{
		"tags":        []string{"alpha", "beta"},
		"by_env":      map[string][]string{"prod": {"a", "b"}},
		"labels":      map[string]string{"tier": "gold"},
		"counts":      []int{1, 2, 3},
		"nested_deep": map[string]any{"inner": []string{"x"}},
	}

	clone := src.Clone()

	clone["tags"].([]string)[0] = "MUTATED"
	if src["tags"].([]string)[0] != "alpha" {
		t.Error("[]string aliased between source and clone")
	}

	clone["by_env"].(map[string][]string)["prod"][0] = "MUTATED"
	if src["by_env"].(map[string][]string)["prod"][0] != "a" {
		t.Error("map[string][]string element slice aliased")
	}

	clone["labels"].(map[string]string)["tier"] = "MUTATED"
	if src["labels"].(map[string]string)["tier"] != "gold" {
		t.Error("map[string]string aliased")
	}

	clone["counts"].([]int)[0] = 99
	if src["counts"].([]int)[0] != 1 {
		t.Error("[]int aliased")
	}

	clone["nested_deep"].(map[string]any)["inner"].([]string)[0] = "MUTATED"
	if src["nested_deep"].(map[string]any)["inner"].([]string)[0] != "x" {
		t.Error("[]string nested under map[string]any aliased")
	}
}

// TestClonePreservesJSONShape guards against the deep copy changing how a
// record serializes, since these clones are what handlers write to the wire.
func TestClonePreservesJSONShape(t *testing.T) {
	blocked := false
	lastLogin := "2026-09-01T00:00:00.000Z"
	src := &User{
		ID:            "auth0|abc",
		Email:         "a@example.test",
		Name:          "A",
		EmailVerified: true,
		Blocked:       &blocked,
		LastLogin:     &lastLogin,
		Identities:    []UserIdentity{{Connection: "email", Provider: "email", UserID: "abc"}},
		AppMetadata: AppMetadata{
			AppMetaTenantID: "org_a",
			AppMetaOrgRoles: map[string]any{"org_a": "admin"},
		},
		UserMetadata:  map[string]any{"pref": map[string]any{"theme": "dark"}},
		Organizations: []string{"org_a"},
	}

	want, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal source: %v", err)
	}
	got, err := json.Marshal(src.Clone())
	if err != nil {
		t.Fatalf("marshal clone: %v", err)
	}
	if string(want) != string(got) {
		t.Errorf("clone serializes differently:\n want %s\n  got %s", want, got)
	}
}

func TestUserCloneIsolatesEveryMutableField(t *testing.T) {
	blocked := false
	lastLogin := "2026-09-01T00:00:00.000Z"
	src := &User{
		ID:            "auth0|abc",
		Blocked:       &blocked,
		LastLogin:     &lastLogin,
		Identities:    []UserIdentity{{Connection: "email"}},
		AppMetadata:   AppMetadata{AppMetaRole: "admin"},
		UserMetadata:  map[string]any{"k": "v"},
		Organizations: []string{"org_a"},
	}

	clone := src.Clone()

	// updateUserMetadata mutates UserMetadata in place; that must not be
	// visible through a clone already handed to a reader.
	clone.UserMetadata["k"] = "MUTATED"
	if src.UserMetadata["k"] != "v" {
		t.Error("UserMetadata aliased")
	}

	clone.AppMetadata[AppMetaRole] = "MUTATED"
	if src.AppMetadata.Role() != "admin" {
		t.Error("AppMetadata aliased")
	}

	clone.Identities[0].Connection = "MUTATED"
	if src.Identities[0].Connection != "email" {
		t.Error("Identities aliased")
	}

	clone.Organizations[0] = "MUTATED"
	if src.Organizations[0] != "org_a" {
		t.Error("Organizations aliased")
	}

	*clone.Blocked = true
	if *src.Blocked {
		t.Error("Blocked pointer aliased")
	}

	*clone.LastLogin = "MUTATED"
	if *src.LastLogin != lastLogin {
		t.Error("LastLogin pointer aliased")
	}
}

func TestOrganizationCloneIsolatesMetadataAndBranding(t *testing.T) {
	src := &Organization{
		ID:       "org_a",
		Metadata: map[string]any{"tenant_id": "t1"},
		Branding: &OrganizationBranding{
			PrimaryColor: "#fff",
			Colors:       map[string]string{"primary": "#fff"},
		},
	}

	clone := src.Clone()

	clone.Metadata["tenant_id"] = "MUTATED"
	if src.Metadata["tenant_id"] != "t1" {
		t.Error("Metadata aliased")
	}

	clone.Branding.Colors["primary"] = "MUTATED"
	if src.Branding.Colors["primary"] != "#fff" {
		t.Error("Branding.Colors aliased")
	}

	clone.Branding.PrimaryColor = "MUTATED"
	if src.Branding.PrimaryColor != "#fff" {
		t.Error("Branding struct aliased")
	}
}

func TestClientAndConnectionCloneIsolateSlices(t *testing.T) {
	client := &Client{
		ClientID:   "c1",
		Callbacks:  []string{"http://a.test"},
		GrantTypes: []string{"authorization_code"},
		JWTConfig:  map[string]any{"alg": "RS256"},
	}
	cc := client.Clone()
	cc.Callbacks[0] = "MUTATED"
	cc.GrantTypes[0] = "MUTATED"
	cc.JWTConfig["alg"] = "MUTATED"
	if client.Callbacks[0] != "http://a.test" {
		t.Error("Client.Callbacks aliased")
	}
	if client.GrantTypes[0] != "authorization_code" {
		t.Error("Client.GrantTypes aliased")
	}
	if client.JWTConfig["alg"] != "RS256" {
		t.Error("Client.JWTConfig aliased")
	}

	conn := &Connection{
		ID:             "con_1",
		EnabledClients: []string{"*"},
		Organizations:  []string{"org_a"},
		Options:        map[string]any{"x": "y"},
	}
	nc := conn.Clone()
	nc.EnabledClients[0] = "MUTATED"
	nc.Organizations[0] = "MUTATED"
	nc.Options["x"] = "MUTATED"
	if conn.EnabledClients[0] != "*" {
		t.Error("Connection.EnabledClients aliased")
	}
	if conn.Organizations[0] != "org_a" {
		t.Error("Connection.Organizations aliased")
	}
	if conn.Options["x"] != "y" {
		t.Error("Connection.Options aliased")
	}
}

// TestCloneNilSafety pins that nil receivers and nil maps survive, so
// omitempty fields stay absent rather than serializing as {}.
func TestCloneNilSafety(t *testing.T) {
	var (
		nilUser *User
		nilOrg  *Organization
		nilConn *Connection
		nilCli  *Client
		nilMeta AppMetadata
	)

	if nilUser.Clone() != nil {
		t.Error("nil *User should clone to nil")
	}
	if nilOrg.Clone() != nil {
		t.Error("nil *Organization should clone to nil")
	}
	if nilConn.Clone() != nil {
		t.Error("nil *Connection should clone to nil")
	}
	if nilCli.Clone() != nil {
		t.Error("nil *Client should clone to nil")
	}
	if nilMeta.Clone() != nil {
		t.Error("nil AppMetadata should clone to nil")
	}

	bare := (&User{ID: "u1"}).Clone()
	if bare.AppMetadata != nil || bare.UserMetadata != nil || bare.Identities != nil || bare.Organizations != nil {
		t.Errorf("nil fields materialized on clone: %+v", bare)
	}

	// A nil value stored inside metadata must stay nil, not become a typed zero.
	withNil := AppMetadata{"absent": nil}.Clone()
	if v, ok := withNil["absent"]; !ok || v != nil {
		t.Errorf("nil metadata value not preserved: %#v (present=%v)", v, ok)
	}
}
