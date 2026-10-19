package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"

	"github.com/46labs/auth0/pkg/config"
)

func tepMgmt(t *testing.T) *management.Management {
	t.Helper()
	_, ts := setupTestServer(t)
	t.Cleanup(ts.Close)
	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func tepAction(t *testing.T, m *management.Management, trigger string) string {
	t.Helper()
	a := &management.Action{
		Name:              auth0.String("cte-" + trigger),
		Code:              auth0.String("exports.onExecuteCustomTokenExchange = async () => {}"),
		Runtime:           auth0.String("node22"),
		SupportedTriggers: []management.ActionTrigger{{ID: auth0.String(trigger), Version: auth0.String("v1")}},
	}
	if err := m.Action.Create(context.Background(), a); err != nil {
		t.Fatalf("create action: %v", err)
	}
	if _, err := m.Action.Deploy(context.Background(), a.GetID()); err != nil {
		t.Fatalf("deploy action: %v", err)
	}
	return a.GetID()
}

func tepProfile(subjectType, actionID string) *management.TokenExchangeProfile {
	return &management.TokenExchangeProfile{
		Name: auth0.String("p-" + subjectType), SubjectTokenType: auth0.String(subjectType),
		ActionID: auth0.String(actionID), Type: auth0.String("custom_authentication"),
	}
}

func tepStatus(t *testing.T, err error, status int) {
	t.Helper()
	var mErr management.Error
	if !errors.As(err, &mErr) || mErr.Status() != status {
		t.Fatalf("err = %v, want %d", err, status)
	}
}

func TestTokenExchangeProfileLifecycle(t *testing.T) {
	m := tepMgmt(t)
	ctx := context.Background()
	p := tepProfile("https://acme.test/cis", tepAction(t, m, TriggerCustomTokenExchange))
	if err := m.TokenExchangeProfile.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := m.TokenExchangeProfile.Read(ctx, p.GetID())
	if err != nil || got.GetSubjectTokenType() != "https://acme.test/cis" || got.CreatedAt == nil {
		t.Fatalf("read = %+v, err %v", got, err)
	}

	if err := m.TokenExchangeProfile.Update(ctx, p.GetID(), &management.TokenExchangeProfile{Name: auth0.String("renamed")}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got, _ = m.TokenExchangeProfile.Read(ctx, p.GetID()); got.GetName() != "renamed" || got.GetActionID() != p.GetActionID() {
		t.Fatalf("after update = %+v", got)
	}

	if err := m.TokenExchangeProfile.Delete(ctx, p.GetID()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = m.TokenExchangeProfile.Read(ctx, p.GetID())
	tepStatus(t, err, http.StatusNotFound)
	if err := m.TokenExchangeProfile.Delete(ctx, p.GetID()); err != nil {
		t.Fatalf("repeat delete: %v", err)
	}
}

func TestTokenExchangeProfileRefusesWhatAuth0Refuses(t *testing.T) {
	m := tepMgmt(t)
	ctx := context.Background()
	cte := tepAction(t, m, TriggerCustomTokenExchange)
	if err := m.TokenExchangeProfile.Create(ctx, tepProfile("https://acme.test/cis", cte)); err != nil {
		t.Fatal(err)
	}

	tepStatus(t, m.TokenExchangeProfile.Create(ctx, tepProfile("https://acme.test/cis", cte)), http.StatusConflict)
	tepStatus(t, m.TokenExchangeProfile.Create(ctx, tepProfile("https://acme.test/other", "missing")), http.StatusBadRequest)
	tepStatus(t, m.TokenExchangeProfile.Create(ctx, tepProfile("https://acme.test/other", tepAction(t, m, TriggerPostLogin))), http.StatusBadRequest)
	noType := tepProfile("https://acme.test/other", cte)
	noType.Type = nil
	tepStatus(t, m.TokenExchangeProfile.Create(ctx, noType), http.StatusBadRequest)
	tepStatus(t, m.TokenExchangeProfile.Update(ctx, "tep_missing", &management.TokenExchangeProfile{Name: auth0.String("renamed")}), http.StatusNotFound)

	// Offset paging's options are refused on this checkpoint endpoint.
	for _, opt := range []management.RequestOption{management.IncludeTotals(true), management.PerPage(10), management.Page(1), management.Take(0), management.Take(101)} {
		_, err := m.TokenExchangeProfile.List(ctx, opt)
		tepStatus(t, err, http.StatusBadRequest)
	}
}

func TestTokenExchangeProfileListPagesByCheckpoint(t *testing.T) {
	m := tepMgmt(t)
	ctx := context.Background()
	cte := tepAction(t, m, TriggerCustomTokenExchange)
	for i := range 5 {
		if err := m.TokenExchangeProfile.Create(ctx, tepProfile(fmt.Sprintf("https://acme.test/%d", i), cte)); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	opts := []management.RequestOption{management.Take(2)}
	for pages := 0; ; pages++ {
		list, err := m.TokenExchangeProfile.List(ctx, opts...)
		if err != nil || pages > 5 {
			t.Fatalf("list: %v after %d pages", err, pages)
		}
		for _, p := range list.TokenExchangeProfiles {
			if seen[p.GetID()] {
				t.Fatalf("%s listed twice", p.GetID())
			}
			seen[p.GetID()] = true
		}
		if !list.HasNext() {
			break
		}
		opts = []management.RequestOption{management.Take(2), management.From(list.Next)}
	}
	if len(seen) != 5 {
		t.Fatalf("listed %d profiles, want 5", len(seen))
	}
}

func TestTokenExchangeProfileRefusesInvalidFields(t *testing.T) {
	m := tepMgmt(t)
	ctx := context.Background()
	cte := tepAction(t, m, TriggerCustomTokenExchange)
	for _, st := range []string{"", "not a uri", "ftp://acme.test/token", "https:///token", "urn:a", "https://acme.test/" + strings.Repeat("x", 90),
		"urn:ietf:params:oauth:token-type:jwt", "https://auth0.com/token", "https://tenant.auth0.com/token", "https://acme.okta.com/t"} {
		tepStatus(t, m.TokenExchangeProfile.Create(ctx, tepProfile(st, cte)), http.StatusBadRequest)
	}
	for _, name := range []string{"", "ab", strings.Repeat("n", 51)} {
		bad := tepProfile("https://acme.test/cis", cte)
		bad.Name = auth0.String(name)
		tepStatus(t, m.TokenExchangeProfile.Create(ctx, bad), http.StatusBadRequest)
	}

	draft := &management.Action{
		Name: auth0.String("draft-cte"), Code: auth0.String("exports.onExecuteCustomTokenExchange = async () => {}"), Runtime: auth0.String("node22"),
		SupportedTriggers: []management.ActionTrigger{{ID: auth0.String(TriggerCustomTokenExchange), Version: auth0.String("v1")}},
	}
	if err := m.Action.Create(ctx, draft); err != nil {
		t.Fatal(err)
	}
	tepStatus(t, m.TokenExchangeProfile.Create(ctx, tepProfile("https://acme.test/draft", draft.GetID())), http.StatusBadRequest)

	// Advertising the trigger is not enough until a version with it is deployed.
	login := tepAction(t, m, TriggerPostLogin)
	if err := m.Action.Update(ctx, login, &management.Action{
		SupportedTriggers: []management.ActionTrigger{{ID: auth0.String(TriggerCustomTokenExchange), Version: auth0.String("v1")}},
	}); err != nil {
		t.Fatal(err)
	}
	tepStatus(t, m.TokenExchangeProfile.Create(ctx, tepProfile("https://acme.test/patched", login)), http.StatusBadRequest)

	// A host that only starts with a reserved domain is not reserved.
	p := tepProfile("https://auth0.com.acme.test/cis", cte)
	if err := m.TokenExchangeProfile.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	tepStatus(t, m.TokenExchangeProfile.Update(ctx, p.GetID(), &management.TokenExchangeProfile{SubjectTokenType: auth0.String("urn:auth0:x")}), http.StatusBadRequest)
}

// A profile binds its action: deleting the action is refused, and forced
// deletion removes the profile with it.
func TestTokenExchangeProfileBindsItsAction(t *testing.T) {
	m := tepMgmt(t)
	ctx := context.Background()
	cte := tepAction(t, m, TriggerCustomTokenExchange)
	p := tepProfile("https://acme.test/cis", cte)
	if err := m.TokenExchangeProfile.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	tepStatus(t, m.Action.Delete(ctx, cte), http.StatusConflict)
	if err := m.Action.Delete(ctx, cte, management.Parameter("force", "true")); err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	_, err := m.TokenExchangeProfile.Read(ctx, p.GetID())
	tepStatus(t, err, http.StatusNotFound)
}

// client_metadata is patched key by key, null removing a key, and validated as
// the SDK documents it.
func TestClientMetadataUpdate(t *testing.T) {
	m := tepMgmt(t)
	ctx := context.Background()
	c := &management.Client{Name: auth0.String("loc"), AppType: auth0.String("non_interactive"), ClientMetadata: &map[string]any{"a": "1", "b": "2"}}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := m.Client.Update(ctx, c.GetClientID(), &management.Client{ClientMetadata: &map[string]any{"org_id": "org_1", "b": nil}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := m.Client.Read(ctx, c.GetClientID())
	md := got.GetClientMetadata()
	if err != nil || md["org_id"] != "org_1" || md["a"] != "1" || md["b"] != nil {
		t.Fatalf("client_metadata = %v, err %v", md, err)
	}
	// The limit counts characters: 200 two-byte characters fit.
	if err := m.Client.Update(ctx, c.GetClientID(), &management.Client{ClientMetadata: &map[string]any{"a": strings.Repeat("é", 200)}}); err != nil {
		t.Fatalf("non-ASCII value: %v", err)
	}

	tooMany := map[string]any{}
	for i := range 9 {
		// With the two stored keys, nine more make eleven.
		tooMany[fmt.Sprintf("k%d", i)] = "v"
	}
	for name, patch := range map[string]map[string]any{
		"non-string value":   {"n": 1},
		"value too long":     {"long": strings.Repeat("x", 256)},
		"key not allowed":    {"bad!key": "v"},
		"more than ten keys": tooMany,
	} {
		t.Run(name, func(t *testing.T) {
			tepStatus(t, m.Client.Update(ctx, c.GetClientID(), &management.Client{ClientMetadata: &patch}), http.StatusBadRequest)
		})
	}
	tepStatus(t, m.Client.Create(ctx, &management.Client{Name: auth0.String("x"), ClientMetadata: &map[string]any{"bad!key": "v"}}), http.StatusBadRequest)
	if got, _ = m.Client.Read(ctx, c.GetClientID()); len(got.GetClientMetadata()) != 2 {
		t.Fatalf("a refused update changed client_metadata: %v", got.GetClientMetadata())
	}
}

// Token requests read the client while metadata updates replace it; under
// -race this proves the token path works on a copy.
func TestClientMetadataUpdateRacesTokenIssuance(t *testing.T) {
	srv, ts := setupTestServer(t)
	t.Cleanup(ts.Close)
	// A claim from client metadata, so the token path reads it.
	srv.cfg.Actions.CredentialsExchange = &config.CredentialsExchangeAction{
		AccessTokenClaims: map[string]string{"i": "${client.metadata.i}"},
	}
	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = m.Client.Update(context.Background(), "mgmt_client_dev", &management.Client{ClientMetadata: &map[string]any{"i": fmt.Sprint(i)}})
		}()
		go func() {
			defer wg.Done()
			resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
				"grant_type": {"client_credentials"}, "client_id": {"mgmt_client_dev"},
				"client_secret": {"mgmt_secret_dev"}, "audience": {"http://localhost:3000"},
			})
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
}
