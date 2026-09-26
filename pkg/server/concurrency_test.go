package server

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/auth0/go-auth0/management"
)

var sessionIDRe = regexp.MustCompile(`name="session_id"[^>]*value="([^"]*)"`)

const testRedirectURI = "http://localhost:3000/callback"

// issueAuthCode drives authorize -> verification code and returns the issued
// authorization code without exchanging it. Errors are reported on t, which is
// safe to call from parallel goroutines.
func issueAuthCode(t *testing.T, baseURL, identifier string) string {
	t.Helper()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authURL := baseURL + "/authorize?response_type=code&client_id=test_client&scope=openid+profile+email+offline_access&redirect_uri=" + url.QueryEscape(testRedirectURI)

	resp, err := client.Get(authURL)
	if err != nil {
		t.Errorf("GET /authorize: %v", err)
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	m := sessionIDRe.FindStringSubmatch(string(body))
	if len(m) < 2 {
		t.Errorf("no session_id in login page")
		return ""
	}

	resp2, err := client.PostForm(baseURL+"/authorize", url.Values{
		"session_id": {m[1]},
		"identifier": {identifier},
		"code":       {"123456"},
	})
	if err != nil {
		t.Errorf("POST /authorize: %v", err)
		return ""
	}
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusFound {
		t.Errorf("expected 302 from /authorize, got %d", resp2.StatusCode)
		return ""
	}
	loc, err := url.Parse(resp2.Header.Get("Location"))
	if err != nil {
		t.Errorf("bad Location header: %v", err)
		return ""
	}
	authCode := loc.Query().Get("code")
	if authCode == "" {
		t.Errorf("no code in redirect: %s", resp2.Header.Get("Location"))
		return ""
	}
	return authCode
}

// runLogin drives one full authorize -> code -> token exchange over HTTP and
// returns the (now consumed) auth code.
func runLogin(t *testing.T, baseURL, identifier string) string {
	t.Helper()

	authCode := issueAuthCode(t, baseURL, identifier)
	if authCode == "" {
		return ""
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp3, err := client.PostForm(baseURL+"/oauth/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode},
		"client_id":    {"test_client"},
		"redirect_uri": {testRedirectURI},
	})
	if err != nil {
		t.Errorf("POST /oauth/token: %v", err)
		return ""
	}
	tokenBody, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from /oauth/token, got %d: %s", resp3.StatusCode, tokenBody)
		return ""
	}
	if !strings.Contains(string(tokenBody), "access_token") {
		t.Errorf("no access_token in response: %s", tokenBody)
	}
	return authCode
}

// TestConcurrentLoginFlows exercises the authorize -> token path from many
// goroutines at once. The pending/verified/verifiers/nonces/scopes maps are
// all written on this path; run with -race, this fails on unguarded access.
func TestConcurrentLoginFlows(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	const goroutines = 24

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// Distinct identifiers force autoCreateUser writes to s.users
			// concurrently with the login-state writes.
			runLogin(t, ts.URL, "concurrent+"+string(rune('a'+n%26))+"@example.test")
		}(i)
	}
	wg.Wait()
}

// TestConcurrentLoginAndManagementAPI runs logins against Management API
// traffic touching the same maps (users, members, organizations).
func TestConcurrentLoginAndManagementAPI(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	var wg sync.WaitGroup

	for i := range 12 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			runLogin(t, ts.URL, "mixed+"+string(rune('a'+n%26))+"@example.test")
		}(i)
	}

	m, err := management.New(ts.URL, management.WithStaticToken("mock_token"), management.WithInsecure())
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	ctx := context.Background()

	// Concurrent readers of the member/user join and the user record.
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reads := map[string]func() error{
				"Organization.Members": func() error { _, err := m.Organization.Members(ctx, "org_test"); return err },
				"User.Read":            func() error { _, err := m.User.Read(ctx, "test_user_1"); return err },
				"User.Organizations":   func() error { _, err := m.User.Organizations(ctx, "test_user_1"); return err },
				"Organization.List":    func() error { _, err := m.Organization.List(ctx); return err },
			}
			for name, read := range reads {
				if err := read(); err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
		}()
	}

	// Concurrent writer touching app_metadata on a user being read above.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			appMeta := map[string]any{"tenant_id": "org_test", "role": "admin"}
			if err := m.User.Update(ctx, "test_user_1", &management.User{AppMetadata: &appMeta}); err != nil {
				t.Errorf("User.Update: %v", err)
			}
		}()
	}

	wg.Wait()
}

// TestConcurrentAuthCodeExchangeYieldsExactlyOneToken is the real single-use
// test. Sequential replay is easy to pass while still allowing two concurrent
// exchanges to both read the code, both mint tokens, and both answer 200
// before either delete lands. Exactly one request may win.
func TestConcurrentAuthCodeExchangeYieldsExactlyOneToken(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	const attempts = 8

	// Repeat: a lost race is probabilistic, so one round could pass by luck.
	for round := range 12 {
		authCode := issueAuthCode(t, ts.URL, "race+"+string(rune('a'+round%26))+"@example.test")
		if authCode == "" {
			t.Fatalf("round %d: no code issued", round)
		}

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			granted int
		)
		start := make(chan struct{})

		for range attempts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // release all goroutines together to widen the window
				resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
					"grant_type": {"authorization_code"},
					"code":       {authCode},
					"client_id":  {"test_client"},
				})
				if err != nil {
					return
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "access_token") {
					mu.Lock()
					granted++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()

		if granted != 1 {
			t.Fatalf("round %d: %d of %d concurrent exchanges of one code were granted; want exactly 1",
				round, granted, attempts)
		}
	}
}

// TestAuthCodeIsSingleUse pins the code-consumption semantics the lock now
// makes atomic: the second exchange of the same code must fail.
func TestAuthCodeIsSingleUse(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	authCode := runLogin(t, ts.URL, "singleuse@example.test")
	if authCode == "" {
		t.Fatal("first login did not yield a code")
	}

	resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {authCode},
		"client_id":  {"test_client"},
	})
	if err != nil {
		t.Fatalf("replay POST /oauth/token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		t.Error("replayed authorization code was accepted; codes must be single-use")
	}
}
