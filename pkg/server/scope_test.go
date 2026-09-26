package server

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func TestGrantedScope(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		want      string
	}{
		{"empty falls back to the default", "", defaultScope},
		{"whitespace falls back to the default", "   ", defaultScope},
		{"api scopes pass through", "openid profile email prayers:write", "openid profile email prayers:write"},
		{"duplicates are dropped in order", "openid openid prayers:read openid", "openid prayers:read"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := grantedScope(tt.requested); got != tt.want {
				t.Fatalf("grantedScope(%q) = %q, want %q", tt.requested, got, tt.want)
			}
		})
	}
}

func accessTokenScope(t *testing.T, raw string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	scope, _ := claims["scope"].(string)
	return scope
}

// The access token carries the scopes the authorize request asked for, and a
// refresh re-issues the same scopes.
func TestAccessTokenScopeFollowsRequestThroughRefresh(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	ctx := context.Background()
	requested := "openid profile email offline_access prayers:write"
	conf := &oauth2.Config{
		ClientID:    "test_client",
		Endpoint:    oauth2.Endpoint{AuthURL: ts.URL + "/authorize", TokenURL: ts.URL + "/oauth/token"},
		RedirectURL: "http://localhost:3000/callback",
	}

	token, err := conf.Exchange(ctx, srv.IssueAuthCode("test_user_1", requested, "", "test_client"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got := accessTokenScope(t, token.AccessToken); got != requested {
		t.Fatalf("access token scope = %q, want %q", got, requested)
	}

	refreshed, err := conf.TokenSource(ctx, &oauth2.Token{
		AccessToken:  "expired",
		RefreshToken: token.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}).Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := accessTokenScope(t, refreshed.AccessToken); got != requested {
		t.Fatalf("refreshed access token scope = %q, want %q", got, requested)
	}
}

func TestAccessTokenScopeDefaultsWhenNoneRequested(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	conf := &oauth2.Config{
		ClientID:    "test_client",
		Endpoint:    oauth2.Endpoint{AuthURL: ts.URL + "/authorize", TokenURL: ts.URL + "/oauth/token"},
		RedirectURL: "http://localhost:3000/callback",
	}

	token, err := conf.Exchange(context.Background(), srv.IssueAuthCode("test_user_1", "", "", "test_client"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got := accessTokenScope(t, token.AccessToken); got != defaultScope {
		t.Fatalf("access token scope = %q, want %q", got, defaultScope)
	}
}
