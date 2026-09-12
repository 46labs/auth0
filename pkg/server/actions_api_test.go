package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"

	"github.com/46labs/auth0/pkg/config"
)

func actionsMgmt(t *testing.T) *management.Management {
	t.Helper()

	srv, err := New(&config.Config{Issuer: "https://auth.test/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	mgmt, err := management.New(strings.TrimPrefix(ts.URL, "http://"),
		management.WithInsecure(), management.WithStaticToken("test-token"))
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	return mgmt
}

// A reconciler reads the offered triggers first and treats a 404 as "this
// upstream has no Actions API", so without this endpoint every later call is
// unreachable and goes untested until a real tenant refuses one.
func TestActionTriggersAreOffered(t *testing.T) {
	mgmt := actionsMgmt(t)

	list, err := mgmt.Action.Triggers(context.Background())
	if err != nil {
		t.Fatalf("Action.Triggers: %v", err)
	}

	// The contract versions matter: a consumer pins the one its source is
	// written against and refuses to deploy against a tenant lacking it.
	want := map[string]string{
		"post-login": "v3", "credentials-exchange": "v2", "custom-token-exchange": "v1",
	}
	got := map[string]string{}
	for _, tr := range list.Triggers {
		got[tr.GetID()] = tr.GetVersion()
	}
	for id, version := range want {
		if got[id] != version {
			t.Errorf("trigger %s = %q, want %q", id, got[id], version)
		}
	}
}

// Auth0 builds asynchronously and a consumer polls Read until the status leaves
// "pending"; without the field that poll spins until it reports the Action
// never finished building.
func TestActionCreateReportsBuilt(t *testing.T) {
	mgmt := actionsMgmt(t)
	ctx := context.Background()

	action := &management.Action{
		Name: auth0.String("pee-post-login"),
		Code: auth0.String("exports.onExecutePostLogin = async () => {};"),
		SupportedTriggers: []management.ActionTrigger{
			{ID: auth0.String("post-login"), Version: auth0.String("v3")},
		},
	}
	if err := mgmt.Action.Create(ctx, action); err != nil {
		t.Fatalf("Action.Create: %v", err)
	}

	read, err := mgmt.Action.Read(ctx, action.GetID())
	if err != nil {
		t.Fatalf("Action.Read: %v", err)
	}
	if read.GetStatus() != "built" {
		t.Fatalf("status = %q, want built", read.GetStatus())
	}
	// Built is not deployed; the deploy call is what flips this.
	if read.AllChangesDeployed {
		t.Fatal("a freshly created action reports its changes deployed")
	}
}

func TestActionDeployMarksChangesDeployed(t *testing.T) {
	mgmt := actionsMgmt(t)
	ctx := context.Background()

	action := &management.Action{Name: auth0.String("pee-post-login"), Code: auth0.String("x")}
	if err := mgmt.Action.Create(ctx, action); err != nil {
		t.Fatalf("Action.Create: %v", err)
	}
	if _, err := mgmt.Action.Deploy(ctx, action.GetID()); err != nil {
		t.Fatalf("Action.Deploy: %v", err)
	}

	read, err := mgmt.Action.Read(ctx, action.GetID())
	if err != nil {
		t.Fatalf("Action.Read: %v", err)
	}
	if !read.AllChangesDeployed {
		t.Fatal("deploy did not mark the changes deployed")
	}
}

// Editing leaves the deployed version behind until the consumer deploys again,
// which is what makes the deploy call load bearing rather than decorative.
func TestActionUpdateClearsDeployed(t *testing.T) {
	mgmt := actionsMgmt(t)
	ctx := context.Background()

	action := &management.Action{Name: auth0.String("pee-post-login"), Code: auth0.String("x")}
	if err := mgmt.Action.Create(ctx, action); err != nil {
		t.Fatalf("Action.Create: %v", err)
	}
	if _, err := mgmt.Action.Deploy(ctx, action.GetID()); err != nil {
		t.Fatalf("Action.Deploy: %v", err)
	}
	if err := mgmt.Action.Update(ctx, action.GetID(),
		&management.Action{Code: auth0.String("changed")}); err != nil {
		t.Fatalf("Action.Update: %v", err)
	}

	read, err := mgmt.Action.Read(ctx, action.GetID())
	if err != nil {
		t.Fatalf("Action.Read: %v", err)
	}
	if read.AllChangesDeployed {
		t.Fatal("an edited action still reports its changes deployed")
	}
	if read.GetStatus() != "built" {
		t.Fatalf("status = %q, want built after the rebuild", read.GetStatus())
	}
}

// A consumer asks for one name and relies on the filter rather than scanning,
// so an unfiltered answer would let it adopt somebody else's Action.
func TestActionListFiltersByName(t *testing.T) {
	mgmt := actionsMgmt(t)
	ctx := context.Background()

	for _, name := range []string{"pee-post-login", "someone-elses"} {
		if err := mgmt.Action.Create(ctx, &management.Action{
			Name: auth0.String(name), Code: auth0.String("x"),
		}); err != nil {
			t.Fatalf("Action.Create %s: %v", name, err)
		}
	}

	list, err := mgmt.Action.List(ctx, management.Parameter("actionName", "pee-post-login"))
	if err != nil {
		t.Fatalf("Action.List: %v", err)
	}
	if len(list.Actions) != 1 || list.Actions[0].GetName() != "pee-post-login" {
		t.Fatalf("filtered list returned %d actions", len(list.Actions))
	}
}

func TestActionCreateConflictsOnName(t *testing.T) {
	mgmt := actionsMgmt(t)
	ctx := context.Background()

	if err := mgmt.Action.Create(ctx, &management.Action{
		Name: auth0.String("pee-post-login"), Code: auth0.String("x"),
	}); err != nil {
		t.Fatalf("Action.Create: %v", err)
	}
	err := mgmt.Action.Create(ctx, &management.Action{
		Name: auth0.String("pee-post-login"), Code: auth0.String("y"),
	})
	if err == nil {
		t.Fatal("created two actions with the same name")
	}
	if got := statusOf(t, err); got != http.StatusConflict {
		t.Fatalf("status = %d, want 409", got)
	}
}

// Auth0 replaces the whole binding list on PATCH, so a consumer that appends
// has to send everything it wants to keep.
func TestTriggerBindingsRoundTrip(t *testing.T) {
	mgmt := actionsMgmt(t)
	ctx := context.Background()

	action := &management.Action{Name: auth0.String("pee-post-login"), Code: auth0.String("x")}
	if err := mgmt.Action.Create(ctx, action); err != nil {
		t.Fatalf("Action.Create: %v", err)
	}

	if err := mgmt.Action.UpdateBindings(ctx, "post-login", []*management.ActionBinding{{
		Ref: &management.ActionBindingReference{
			Type: auth0.String("action_name"), Value: auth0.String("pee-post-login"),
		},
		DisplayName: auth0.String("pee-post-login"),
	}}); err != nil {
		t.Fatalf("UpdateBindings: %v", err)
	}

	bound, err := mgmt.Action.Bindings(ctx, "post-login")
	if err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if len(bound.Bindings) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bound.Bindings))
	}
	// A consumer reads the action's name off the binding to tell its own from
	// somebody else's, and Auth0 answers with the action rather than the ref.
	if bound.Bindings[0].Action.GetName() != "pee-post-login" {
		t.Fatal("the binding does not carry the bound action")
	}
}

// This listing is checkpoint-paginated and Auth0 rejects include_totals
// outright. The mock accepting it is what let that bug reach production.
func TestTokenExchangeProfilesRejectIncludeTotals(t *testing.T) {
	mgmt := actionsMgmt(t)

	_, err := mgmt.TokenExchangeProfile.List(context.Background(), management.IncludeTotals(true))
	if err == nil {
		t.Fatal("accepted include_totals, which Auth0 refuses on this endpoint")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

func TestTokenExchangeProfileCreateAndList(t *testing.T) {
	mgmt := actionsMgmt(t)
	ctx := context.Background()

	action := &management.Action{Name: auth0.String("pee-cte"), Code: auth0.String("x")}
	if err := mgmt.Action.Create(ctx, action); err != nil {
		t.Fatalf("Action.Create: %v", err)
	}

	if err := mgmt.TokenExchangeProfile.Create(ctx, &management.TokenExchangeProfile{
		Name:             auth0.String("pee-cte"),
		SubjectTokenType: auth0.String("urn:pee:token-type:platform-admin"),
		ActionID:         auth0.String(action.GetID()),
		Type:             auth0.String("custom_authentication"),
	}); err != nil {
		t.Fatalf("TokenExchangeProfile.Create: %v", err)
	}

	list, err := mgmt.TokenExchangeProfile.List(ctx, management.Take(100))
	if err != nil {
		t.Fatalf("TokenExchangeProfile.List: %v", err)
	}
	if len(list.TokenExchangeProfiles) != 1 {
		t.Fatalf("profiles = %d, want 1", len(list.TokenExchangeProfiles))
	}
	if list.TokenExchangeProfiles[0].GetActionID() != action.GetID() {
		t.Fatal("the profile does not point at the action that was created")
	}
}

// A second profile for the same subject token type would make which Action runs
// ambiguous, and a consumer checks for exactly this before creating one.
func TestTokenExchangeProfileConflictsOnSubjectType(t *testing.T) {
	mgmt := actionsMgmt(t)
	ctx := context.Background()

	create := func(name string) error {
		action := &management.Action{Name: auth0.String(name), Code: auth0.String("x")}
		if err := mgmt.Action.Create(ctx, action); err != nil {
			t.Fatalf("Action.Create: %v", err)
		}
		return mgmt.TokenExchangeProfile.Create(ctx, &management.TokenExchangeProfile{
			Name:             auth0.String(name),
			SubjectTokenType: auth0.String("urn:pee:token-type:platform-admin"),
			ActionID:         auth0.String(action.GetID()),
			Type:             auth0.String("custom_authentication"),
		})
	}

	if err := create("first"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	err := create("second")
	if err == nil {
		t.Fatal("created a second profile for the same subject token type")
	}
	if got := statusOf(t, err); got != http.StatusConflict {
		t.Fatalf("status = %d, want 409", got)
	}
}
