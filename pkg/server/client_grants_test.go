package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/46labs/auth0/pkg/config"
)

// Driven through the official SDK: the wire shapes only matter insofar as
// go-auth0 decodes them, and a consumer provisioning credentials reaches these
// endpoints through exactly these methods.
func grantMgmt(t *testing.T) (*Server, *management.Management, *httptest.Server) {
	t.Helper()
	srv, ts := setupTestServer(t)
	t.Cleanup(ts.Close)

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	return srv, m, ts
}

func TestClientGrantCreateAndList(t *testing.T) {
	_, m, _ := grantMgmt(t)
	ctx := context.Background()

	c := &management.Client{Name: auth0.String("loc-edge01"), AppType: auth0.String("non_interactive")}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Create client: %v", err)
	}

	if err := m.ClientGrant.Create(ctx, &management.ClientGrant{
		ClientID: auth0.String(c.GetClientID()),
		Audience: auth0.String("https://api.example"),
		Scope:    &[]string{},
	}); err != nil {
		t.Fatalf("Create grant: %v", err)
	}

	// The filter is what a reconciler uses to stay idempotent.
	got, err := m.ClientGrant.List(ctx,
		management.Parameter("client_id", c.GetClientID()),
		management.Parameter("audience", "https://api.example"),
		management.IncludeTotals(true),
	)
	if err != nil {
		t.Fatalf("List grants: %v", err)
	}
	if len(got.ClientGrants) != 1 {
		t.Fatalf("grants = %d, want 1", len(got.ClientGrants))
	}

	// A filter that matches nothing must return nothing, or a reconciler would
	// believe a grant exists and skip creating it.
	none, err := m.ClientGrant.List(ctx,
		management.Parameter("client_id", "cid_other"),
		management.IncludeTotals(true),
	)
	if err != nil {
		t.Fatalf("List grants: %v", err)
	}
	if len(none.ClientGrants) != 0 {
		t.Fatalf("filter leaked %d grants", len(none.ClientGrants))
	}
}

// Auth0 refuses a duplicate pairing rather than creating a second grant.
func TestClientGrantDuplicateIsAConflict(t *testing.T) {
	_, m, _ := grantMgmt(t)
	ctx := context.Background()

	c := &management.Client{Name: auth0.String("loc-edge02")}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Create client: %v", err)
	}
	grant := func() error {
		return m.ClientGrant.Create(ctx, &management.ClientGrant{
			ClientID: auth0.String(c.GetClientID()),
			Audience: auth0.String("https://api.example"),
			Scope:    &[]string{},
		})
	}
	if err := grant(); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	err := grant()
	if err == nil {
		t.Fatal("a duplicate grant was accepted")
	}
	var mgmtErr management.Error
	if !errors.As(err, &mgmtErr) || mgmtErr.Status() != http.StatusConflict {
		t.Fatalf("err = %v, want 409", err)
	}
}

func TestClientGrantRejectsUnknownClient(t *testing.T) {
	_, m, _ := grantMgmt(t)

	err := m.ClientGrant.Create(context.Background(), &management.ClientGrant{
		ClientID: auth0.String("cid_nope"),
		Audience: auth0.String("https://api.example"),
	})
	if err == nil {
		t.Fatal("a grant was created for a client that does not exist")
	}
}

// A grant outliving its client keeps answering list queries and reads as a
// working authorization for an application that is gone.
func TestClientGrantsGoWithTheirClient(t *testing.T) {
	_, m, _ := grantMgmt(t)
	ctx := context.Background()

	c := &management.Client{Name: auth0.String("loc-edge03")}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Create client: %v", err)
	}
	if err := m.ClientGrant.Create(ctx, &management.ClientGrant{
		ClientID: auth0.String(c.GetClientID()),
		Audience: auth0.String("https://api.example"),
		Scope:    &[]string{},
	}); err != nil {
		t.Fatalf("Create grant: %v", err)
	}
	if err := m.Client.Delete(ctx, c.GetClientID()); err != nil {
		t.Fatalf("Delete client: %v", err)
	}

	got, err := m.ClientGrant.List(ctx, management.IncludeTotals(true))
	if err != nil {
		t.Fatalf("List grants: %v", err)
	}
	if len(got.ClientGrants) != 0 {
		t.Fatalf("grant survived its client: %+v", got.ClientGrants)
	}
}

// Rotation is the only recovery for a lost secret, since Auth0 discloses it
// once at creation.
func TestRotateClientSecretReplacesIt(t *testing.T) {
	_, m, _ := grantMgmt(t)
	ctx := context.Background()

	c := &management.Client{Name: auth0.String("loc-edge04")}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Create client: %v", err)
	}
	before := c.GetClientSecret()

	rotated, err := m.Client.RotateSecret(ctx, c.GetClientID())
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if rotated.GetClientSecret() == "" || rotated.GetClientSecret() == before {
		t.Fatalf("secret not rotated: %q -> %q", before, rotated.GetClientSecret())
	}

	// And the stored client must carry the new one, or the old secret keeps
	// authenticating.
	read, err := m.Client.Read(ctx, c.GetClientID())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if read.GetClientSecret() != rotated.GetClientSecret() {
		t.Fatalf("stored secret = %q, want the rotated one", read.GetClientSecret())
	}
}

// m2mToken fetches a token the way a real consumer does. go-auth0 obtains its
// own token through golang.org/x/oauth2 clientcredentials, and so does the
// service these credentials are issued for, so the claims are asserted against
// what that client actually decodes rather than a hand-built form post.
func m2mToken(t *testing.T, tokenURL, clientID, clientSecret, audience string) jwt.MapClaims {
	t.Helper()

	cfg := clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL + "/oauth/token",
		EndpointParams: url.Values{"audience": {audience}},
	}
	tok, err := cfg.Token(context.Background())
	if err != nil {
		t.Fatalf("client credentials token: %v", err)
	}

	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tok.AccessToken, claims); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return claims
}

// An M2M credential carries its organization through client metadata, because
// client-credentials cannot enter an organization context. Without this the
// consumer falls back to an unauthenticated header.
func TestClientCredentialsTokenCarriesMetadataClaims(t *testing.T) {
	srv, m, ts := grantMgmt(t)
	ctx := context.Background()

	srv.cfg.Actions.CredentialsExchange = &config.CredentialsExchangeAction{
		AccessTokenClaims: map[string]string{"org_id": "${client.metadata.org_id}"},
	}
	c := &management.Client{
		Name:       auth0.String("loc-edge05"),
		AppType:    auth0.String("non_interactive"),
		GrantTypes: &[]string{"client_credentials"},
		ClientMetadata: &map[string]any{
			"org_id": "org_acme",
		},
	}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Create client: %v", err)
	}

	claims := m2mToken(t, ts.URL, c.GetClientID(), c.GetClientSecret(), "https://api.example")
	key := strings.TrimSuffix(srv.cfg.Issuer, "/") + "/org_id"
	if claims[key] != "org_acme" {
		t.Fatalf("token carries no organization at %s: %v", key, claims)
	}
}

// A metadata key that is not set omits the claim rather than stamping an empty
// one, mirroring the `if (md.x)` guard a real action uses.
func TestClientCredentialsOmitsUnsetMetadataClaims(t *testing.T) {
	srv, m, ts := grantMgmt(t)
	ctx := context.Background()

	srv.cfg.Actions.CredentialsExchange = &config.CredentialsExchangeAction{
		AccessTokenClaims: map[string]string{"org_id": "${client.metadata.org_id}"},
	}
	c := &management.Client{
		Name:       auth0.String("loc-edge06"),
		GrantTypes: &[]string{"client_credentials"},
	}
	if err := m.Client.Create(ctx, c); err != nil {
		t.Fatalf("Create client: %v", err)
	}

	claims := m2mToken(t, ts.URL, c.GetClientID(), c.GetClientSecret(), "https://api.example")
	key := strings.TrimSuffix(srv.cfg.Issuer, "/") + "/org_id"
	if _, ok := claims[key]; ok {
		t.Fatalf("an unset metadata key produced a claim: %v", claims[key])
	}
}
