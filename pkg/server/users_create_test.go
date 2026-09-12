package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"

	"github.com/46labs/auth0/pkg/config"
)

// passwordlessMgmt drives the Management API through the official SDK, which is
// the only way to prove these wire shapes decode for a real client.
func passwordlessMgmt(t *testing.T, users []config.User) (*management.Management, *httptest.Server) {
	t.Helper()

	srv, err := New(&config.Config{
		Issuer: "https://auth.test/",
		Users:  users,
		Connections: []config.Connection{
			{ID: "con_email", Name: "email", Strategy: "email"},
			{ID: "con_sms", Name: "sms", Strategy: "sms"},
			{ID: "con_entra", Name: "46labs-entra", Strategy: "oidc"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	mgmt, err := management.New(
		strings.TrimPrefix(ts.URL, "http://"),
		management.WithInsecure(),
		management.WithStaticToken("test-token"),
	)
	if err != nil {
		t.Fatalf("management.New: %v", err)
	}
	return mgmt, ts
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var mErr management.Error
	if !errors.As(err, &mErr) {
		t.Fatalf("error is not a management.Error: %v", err)
	}
	return mErr.Status()
}

// A consumer that asks for one strategy and takes the first result would
// otherwise get whichever connection sorts first, passing here and matching
// nothing against a real tenant.
func TestListConnectionsFiltersByStrategy(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	list, err := mgmt.Connection.List(context.Background(),
		management.Parameter("strategy", "email"),
		management.IncludeTotals(true))
	if err != nil {
		t.Fatalf("Connection.List: %v", err)
	}
	if len(list.Connections) != 1 {
		t.Fatalf("connections = %d, want only the email one", len(list.Connections))
	}
	if list.Connections[0].GetStrategy() != "email" {
		t.Fatalf("strategy = %q", list.Connections[0].GetStrategy())
	}
}

func TestListConnectionsWithoutStrategyReturnsAll(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	list, err := mgmt.Connection.List(context.Background(), management.IncludeTotals(true))
	if err != nil {
		t.Fatalf("Connection.List: %v", err)
	}
	if len(list.Connections) != 3 {
		t.Fatalf("connections = %d, want all three", len(list.Connections))
	}
}

func TestCreateUserStoresTheConnectionIdentity(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	user := &management.User{
		Email:      auth0.String("Someone@Example.com"),
		Connection: auth0.String("email"),
	}
	if err := mgmt.User.Create(context.Background(), user); err != nil {
		t.Fatalf("User.Create: %v", err)
	}

	// The address a consumer looks up by is the normalized one.
	if user.GetEmail() != "someone@example.com" {
		t.Fatalf("email = %q, want it lowercased", user.GetEmail())
	}
	// Without the identity, a lookup by connection finds nothing and the
	// consumer creates a duplicate on every call.
	if len(user.Identities) != 1 || user.Identities[0].GetConnection() != "email" {
		t.Fatalf("identities = %+v", user.Identities)
	}
	// Auth0 suffixes the root id with the identity's own subject; linking code
	// addresses that identity by it.
	subject := user.Identities[0].GetUserID()
	if subject == "" || user.GetID() != "email|"+subject {
		t.Fatalf("id %q does not carry identity subject %q", user.GetID(), subject)
	}
}

// A 201 that loses what the caller sent is the false success AGENTS.md warns
// about: the bug surfaces later, somewhere else.
func TestCreateUserPreservesSDKFields(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	user := &management.User{
		Email:        auth0.String("someone@example.com"),
		Connection:   auth0.String("email"),
		Name:         auth0.String("Someone"),
		Picture:      auth0.String("https://pic.test/a.png"),
		Blocked:      auth0.Bool(true),
		UserMetadata: &map[string]interface{}{"theme": "dark"},
	}
	if err := mgmt.User.Create(context.Background(), user); err != nil {
		t.Fatalf("User.Create: %v", err)
	}

	read, err := mgmt.User.Read(context.Background(), user.GetID())
	if err != nil {
		t.Fatalf("User.Read: %v", err)
	}
	if read.GetName() != "Someone" || read.GetPicture() != "https://pic.test/a.png" {
		t.Fatalf("name/picture not stored: %q %q", read.GetName(), read.GetPicture())
	}
	if !read.GetBlocked() {
		t.Fatal("blocked was dropped")
	}
	if md := read.GetUserMetadata(); md["theme"] != "dark" {
		t.Fatalf("user_metadata = %v", md)
	}
}

// Auth0 creates users only in connections it owns the credentials for. A
// federated connection has no user to create, and answering 201 here would let
// a caller pass locally and fail against a real tenant.
func TestCreateUserRejectsAFederatedConnection(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	err := mgmt.User.Create(context.Background(), &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("46labs-entra"),
	})
	if err == nil {
		t.Fatal("created a user in an oidc connection, which Auth0 refuses")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

func TestCreateUserRejectsAnUnknownConnection(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	err := mgmt.User.Create(context.Background(), &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("no-such-connection"),
	})
	if err == nil {
		t.Fatal("created a user in a connection that does not exist")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// The identifier an sms connection wants is the phone number, so requiring an
// email would reject a valid SDK request.
func TestCreateUserAcceptsAnSMSConnection(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	user := &management.User{
		PhoneNumber: auth0.String("+12145551234"),
		Connection:  auth0.String("sms"),
	}
	if err := mgmt.User.Create(context.Background(), user); err != nil {
		t.Fatalf("User.Create for sms: %v", err)
	}
	if user.GetPhoneNumber() != "+12145551234" {
		t.Fatalf("phone = %q", user.GetPhoneNumber())
	}
}

// Auth0 refuses a second user for the same address in the same connection, and
// a consumer that loses the race re-reads instead of failing — which it can
// only do if the status says conflict.
func TestCreateUserConflictsOnTheSameConnection(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, []config.User{{
		ID:         "email|existing",
		Email:      "someone@example.com",
		Identities: []config.UserIdentity{{Connection: "email", Provider: "email"}},
	}})

	err := mgmt.User.Create(context.Background(), &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("email"),
	})
	if err == nil {
		t.Fatal("created a duplicate identity in the same connection")
	}
	if got := statusOf(t, err); got != http.StatusConflict {
		t.Fatalf("status = %d, want 409", got)
	}
}

// The same address in two connections is two users to Auth0, so an existing SSO
// identity must not block creating the passwordless one.
func TestCreateUserAllowsTheSameEmailInAnotherConnection(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, []config.User{{
		ID:         "waad|sso",
		Email:      "someone@example.com",
		Identities: []config.UserIdentity{{Connection: "46labs-entra", Provider: "oidc"}},
	}})

	err := mgmt.User.Create(context.Background(), &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("email"),
	})
	if err != nil {
		t.Fatalf("User.Create: %v", err)
	}
}

// ListByEmail matches what Auth0 stored. Auth0 lowercases its own addresses but
// keeps a federated provider's capitalization, so a case-insensitive match here
// would let a caller pass locally and get nothing from a real tenant.
func TestUsersByEmailMatchesStoredCase(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, []config.User{
		{ID: "waad|federated", Email: "Someone@Example.com",
			Identities: []config.UserIdentity{{Connection: "46labs-entra"}}},
	})

	found, err := mgmt.User.ListByEmail(context.Background(), "Someone@Example.com")
	if err != nil {
		t.Fatalf("ListByEmail: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("exact-case query found %d, want 1", len(found))
	}

	missed, err := mgmt.User.ListByEmail(context.Background(), "someone@example.com")
	if err != nil {
		t.Fatalf("ListByEmail: %v", err)
	}
	if len(missed) != 0 {
		t.Fatalf("wrong-case query found %d, want 0 as Auth0 answers", len(missed))
	}
}

func TestUsersByEmailReturnsEveryIdentityForTheAddress(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, []config.User{
		{ID: "email|a", Email: "someone@example.com",
			Identities: []config.UserIdentity{{Connection: "email"}}},
		{ID: "waad|b", Email: "someone@example.com",
			Identities: []config.UserIdentity{{Connection: "46labs-entra"}}},
		{ID: "email|other", Email: "nobody@example.com"},
	})

	found, err := mgmt.User.ListByEmail(context.Background(), "someone@example.com")
	if err != nil {
		t.Fatalf("ListByEmail: %v", err)
	}
	// Both identities, so the caller can pick the connection it wants; the
	// unrelated address must not appear.
	if len(found) != 2 {
		t.Fatalf("users = %d, want the two for this address", len(found))
	}
}

// Raw HTTP on purpose: this asserts the JSON shape itself, which the SDK's
// typed decode hides. Auth0 answers this endpoint with a bare array rather than
// the paginated envelope the other list endpoints use.
func TestUsersByEmailReturnsABareArray(t *testing.T) {
	_, ts := passwordlessMgmt(t, []config.User{
		{ID: "email|a", Email: "someone@example.com"},
		{ID: "email|b", Email: "someone@example.com"},
		{ID: "email|c", Email: "someone@example.com"},
		{ID: "email|d", Email: "someone@example.com"},
	})

	resp, err := http.Get(ts.URL + "/api/v2/users-by-email?email=someone@example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var users []config.User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		t.Fatalf("decode as array: %v", err)
	}
	if len(users) != 4 {
		t.Fatalf("users = %d", len(users))
	}
	// Map order is random, so an unsorted answer makes a caller that takes the
	// first match behave differently run to run. Four, not two: with two an
	// unsorted map lands in order half the time and this would miss it.
	for i := 1; i < len(users); i++ {
		if users[i-1].ID > users[i].ID {
			t.Fatalf("results are not ordered: %v", users)
		}
	}
}

// One address can hold an identity in several connections, and they are
// different users. Resolving a login by identifier alone picks whichever the
// map yields first, so a passwordless login could be issued a token for the
// enterprise user.
func TestFindUserForConnectionPicksTheRequestedIdentity(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_email", Name: "email", Strategy: "email"}},
		// The SSO id sorts first on purpose: the deterministic fallback would
		// return it, so this only passes because the connection is honoured.
		Users: []config.User{
			{ID: "aaa-waad|sso", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "46labs-entra"}}},
			{ID: "zzz-email|pwdless", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "email"}}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for range 50 {
		got := srv.findUserForConnection("someone@example.com", "email")
		if got == nil || got.ID != "zzz-email|pwdless" {
			t.Fatalf("resolved %v, want the email identity every time", got)
		}
	}
}

// Without a connection the caller has nothing to disambiguate with, so the
// answer must at least be the same one every time.
func TestFindUserIsDeterministicAcrossDuplicates(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer: "https://auth.test/",
		Users: []config.User{
			{ID: "waad|sso", Email: "someone@example.com"},
			{ID: "email|pwdless", Email: "someone@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first := srv.findUser("someone@example.com")
	for range 50 {
		got := srv.findUser("someone@example.com")
		if got == nil || got.ID != first.ID {
			t.Fatalf("resolved %v then %v", first, got)
		}
	}
}

// Database creation needs a password and an auth0| subject, neither of which
// this implements. Answering 201 without them would be a false success.
func TestCreateUserRejectsADatabaseConnection(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_db", Name: "db", Strategy: "auth0"}},
	})
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

	createErr := mgmt.User.Create(context.Background(), &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("db"),
	})
	if createErr == nil {
		t.Fatal("created a database user without a password")
	}
	if got := statusOf(t, createErr); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// Auth0 rejects a malformed address. Storing one produces a local user that
// passes here and does not exist against a real tenant.
func TestCreateUserRejectsAMalformedEmail(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	err := mgmt.User.Create(context.Background(), &management.User{
		Email:      auth0.String("not-an-email"),
		Connection: auth0.String("email"),
	})
	if err == nil {
		t.Fatal("stored a malformed address")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// A number that will not normalize can never be matched again, so the user it
// creates is unusable — worse than refusing the request.
func TestCreateUserRejectsAMalformedPhone(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	err := mgmt.User.Create(context.Background(), &management.User{
		PhoneNumber: auth0.String("123"),
		Connection:  auth0.String("sms"),
	})
	if err == nil {
		t.Fatal("stored a phone number that cannot be looked up")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// Auth0 requires E.164 on the way in rather than normalizing loose formats, so
// accepting this would pass locally and 400 against a real tenant.
func TestCreateUserRejectsANonE164Phone(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	err := mgmt.User.Create(context.Background(), &management.User{
		PhoneNumber: auth0.String("(214) 555-1234"),
		Connection:  auth0.String("sms"),
	})
	if err == nil {
		t.Fatal("accepted a phone number Auth0 refuses")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// The SDK sends these on a create and Auth0 returns them on a read.
func TestCreateUserPreservesProfileFields(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	user := &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("email"),
		GivenName:  auth0.String("Some"),
		FamilyName: auth0.String("One"),
		Nickname:   auth0.String("somey"),
	}
	if err := mgmt.User.Create(context.Background(), user); err != nil {
		t.Fatalf("User.Create: %v", err)
	}

	read, err := mgmt.User.Read(context.Background(), user.GetID())
	if err != nil {
		t.Fatalf("User.Read: %v", err)
	}
	if read.GetGivenName() != "Some" || read.GetFamilyName() != "One" {
		t.Fatalf("names dropped: %q %q", read.GetGivenName(), read.GetFamilyName())
	}
	if read.GetNickname() != "somey" {
		t.Fatalf("nickname dropped: %q", read.GetNickname())
	}
}

// Several users hold this address, so the connection is the only thing that
// says which is logging in; guessing hands a passwordless login the SSO user.
func TestFindUserForConnectionRefusesToGuessAmongDuplicates(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_email", Name: "email", Strategy: "email"}},
		Users: []config.User{
			{ID: "aaa-waad|sso", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "46labs-entra"}}},
			{ID: "bbb-waad|other", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "okta"}}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := srv.findUserForConnection("someone@example.com", "email"); got != nil {
		t.Fatalf("resolved %v, want nil so the caller creates the right identity", got.ID)
	}
}

// A lone match belonging to another connection is still the wrong identity for
// a passwordless login: the mock can create the right one, so it must not mint
// a token for the enterprise subject instead.
func TestFindUserForConnectionRefusesALoneMismatch(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_email", Name: "email", Strategy: "email"}},
		Users: []config.User{
			{ID: "waad|sso", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "46labs-entra"}}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := srv.findUserForConnection("someone@example.com", "email"); got != nil {
		t.Fatalf("resolved %v for a passwordless login, want nil", got.ID)
	}
}

// A federated connection is decided by the IdP, not by the local identity list,
// so a seeded user carrying only another identity must still log in.
func TestFindUserForConnectionFallsBackForFederated(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer: "https://auth.test/",
		Connections: []config.Connection{
			{ID: "con_email", Name: "email", Strategy: "email"},
			{ID: "con_sso", Name: "enterprise-sso", Strategy: "oidc"},
		},
		Users: []config.User{
			{ID: "seeded", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "sms"}}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got := srv.findUserForConnection("someone@example.com", "enterprise-sso")
	if got == nil || got.ID != "seeded" {
		t.Fatalf("resolved %v, want the seeded user", got)
	}
}

// Only a connection that requires a username accepts one, which neither
// passwordless strategy does; Auth0 refuses rather than storing it.
func TestCreateUserRejectsAUsernameOnPasswordless(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	err := mgmt.User.Create(context.Background(), &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("email"),
		Username:   auth0.String("someone"),
	})
	if err == nil {
		t.Fatal("accepted a username on a passwordless connection")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// Auth0 returns email|... even when the connection carries a custom name; the
// custom name lives on the identity instead.
func TestCreateUserPrefixesTheIDWithTheProvider(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_x", Name: "custom-email", Strategy: "email"}},
	})
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

	user := &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("custom-email"),
	}
	if createErr := mgmt.User.Create(context.Background(), user); createErr != nil {
		t.Fatalf("User.Create: %v", createErr)
	}
	if !strings.HasPrefix(user.GetID(), "email|") {
		t.Fatalf("id = %q, want an email| prefix", user.GetID())
	}
	if user.Identities[0].GetConnection() != "custom-email" {
		t.Fatalf("identity connection = %q, want the custom name", user.Identities[0].GetConnection())
	}
}

// Splitting the display name is a guess for users that carry no explicit
// values; returning the guess over the stored profile would contradict what
// the Management API reports for the same user.
func TestIDTokenPrefersExplicitNameFields(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_email", Name: "email", Strategy: "email"}},
		Users: []config.User{{
			ID:         "email|named",
			Email:      "someone@example.com",
			Name:       "Wrong Guess",
			GivenName:  "Explicit",
			FamilyName: "Surname",
			Nickname:   "nick",
			Identities: []config.UserIdentity{{Connection: "email"}},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	code := srv.IssueAuthCode("email|named", "openid profile", "", "test_client")
	if code == "" {
		t.Fatal("no code issued")
	}
	resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
		"client_id":  {"test_client"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode: %v", err)
	}

	claims := claimsOf(t, srv, tokens.IDToken)
	if claims["given_name"] != "Explicit" || claims["family_name"] != "Surname" {
		t.Fatalf("names = %v %v, want the explicit ones", claims["given_name"], claims["family_name"])
	}
	if claims["nickname"] != "nick" {
		t.Fatalf("nickname = %v", claims["nickname"])
	}
}

// The documented YAML user shape omits identities, so a configured user says
// nothing about which connection it belongs to. Refusing it would create a
// duplicate that lacks the original's organization membership.
func TestFindUserForConnectionKeepsIdentitylessFixtures(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_email", Name: "email", Strategy: "email"}},
		Users:       []config.User{{ID: "seeded", Email: "someone@example.com"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got := srv.findUserForConnection("someone@example.com", "email")
	if got == nil || got.ID != "seeded" {
		t.Fatalf("resolved %v, want the seeded user rather than a duplicate", got)
	}
}

// A connection named anything but "email" would never match on the next login:
// the lookup misses, another subject is created, and the user's id changes
// every time they sign in.
func TestAutoCreateRecordsTheRequestedConnection(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_x", Name: "custom-email", Strategy: "email"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first := srv.autoCreateUserForConnection("someone@example.com", "custom-email")
	if first == nil {
		t.Fatal("no user created")
	}
	if first.Identities[0].Connection != "custom-email" {
		t.Fatalf("identity connection = %q", first.Identities[0].Connection)
	}
	// The whole point: the next login finds this one instead of making another.
	again := srv.findUserForConnection("someone@example.com", "custom-email")
	if again == nil || again.ID != first.ID {
		t.Fatalf("second login resolved %v, want the same user %s", again, first.ID)
	}
}

// An enterprise login proves nothing about the address here, so overwriting the
// provider's own verified flag would assert a check that never happened.
func TestFederatedLoginDoesNotOverwriteVerification(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer: "https://auth.test/",
		Connections: []config.Connection{
			{ID: "con_email", Name: "email", Strategy: "email"},
			{ID: "con_sso", Name: "enterprise-sso", Strategy: "oidc"},
		},
		Users: []config.User{{ID: "seeded", Email: "someone@example.com", EmailVerified: false}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	seeded := &config.User{ID: "seeded", Email: "someone@example.com"}
	if srv.isPasswordlessLogin("enterprise-sso", seeded) {
		t.Fatal("an oidc connection is not a passwordless login")
	}
	if !srv.isPasswordlessLogin("email", seeded) {
		t.Fatal("the email connection is a passwordless login")
	}

	// An omitted connection is the passwordless default, but it can still
	// resolve to a federated profile when that is all the address has — and
	// verifying then rewrites a flag the IdP owns.
	federated := &config.User{
		ID:         "waad|sso",
		Email:      "someone@example.com",
		Identities: []config.UserIdentity{{Connection: "enterprise-sso"}},
	}
	if srv.isPasswordlessLogin("", federated) {
		t.Fatal("a federated profile resolved by default must not be treated as passwordless")
	}
}

// A delivered one-time code is the proof of control Auth0 treats as
// verification, so a member pre-created unverified must not stay that way.
func TestPasswordlessLoginMarksTheAddressVerified(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_email", Name: "email", Strategy: "email"}},
		Users: []config.User{{
			ID: "email|member", Email: "someone@example.com", EmailVerified: false,
			Identities: []config.UserIdentity{{Connection: "email"}},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	updated := srv.markIdentifierVerified("email|member", "someone@example.com")
	if updated == nil || !updated.EmailVerified {
		t.Fatalf("address still unverified after a delivered code: %+v", updated)
	}
}

// ParseAddress accepts mailbox syntax, which is not an address Auth0 stores.
func TestCreateUserRejectsMailboxSyntax(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	err := mgmt.User.Create(context.Background(), &management.User{
		Email:      auth0.String("Jane <jane@example.com>"),
		Connection: auth0.String("email"),
	})
	if err == nil {
		t.Fatal("accepted mailbox display-name syntax as an address")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// One address can hold an identity in several connections, so granting the
// invited role to whichever sorted first would hand the membership to a
// different subject than the one authenticating.
func TestInvitationRedemptionIsConnectionScoped(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer: "https://auth.test/",
		Connections: []config.Connection{
			{ID: "con_email", Name: "email", Strategy: "email"},
			{ID: "con_sso", Name: "enterprise-sso", Strategy: "oidc"},
		},
		Users: []config.User{
			{ID: "aaa-email|pwdless", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "email"}}},
			{ID: "zzz-waad|sso", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "enterprise-sso"}}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The passwordless id sorts first, so an unscoped lookup would pick it.
	got := srv.findUserForConnection("someone@example.com", "enterprise-sso")
	if got == nil || got.ID != "zzz-waad|sso" {
		t.Fatalf("resolved %v, want the enterprise subject the invitation is for", got)
	}
}

// Forcing the connection name onto an inferred provider yields an identity no
// Auth0 tenant would return, such as connection=email with provider=sms.
func TestAutoCreateRejectsAnIdentifierTheConnectionCannotHold(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer: "https://auth.test/",
		Connections: []config.Connection{
			{ID: "con_email", Name: "email", Strategy: "email"},
			{ID: "con_sms", Name: "sms", Strategy: "sms"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := srv.autoCreateUserForConnection("+12145551234", "email"); got != nil {
		t.Fatalf("created %v for a phone on an email connection", got.ID)
	}
	if got := srv.autoCreateUserForConnection("someone@example.com", "sms"); got != nil {
		t.Fatalf("created %v for an address on an sms connection", got.ID)
	}
}

// A Management create and a login can race for the same identifier; the second
// writer must find the first's identity rather than insert a duplicate.
func TestAutoCreateDoesNotDuplicateUnderRace(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_email", Name: "email", Strategy: "email"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	ids := make([]string, 8)
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if u := srv.autoCreateUserForConnection("someone@example.com", "email"); u != nil {
				ids[i] = u.ID
			}
		}()
	}
	wg.Wait()

	for i, id := range ids {
		if id == "" {
			t.Fatalf("caller %d got no user", i)
		}
		if id != ids[0] {
			t.Fatalf("callers got different identities: %s and %s", ids[0], id)
		}
	}
}

// A federated provider owns this flag; asserting true would vouch for a number
// nothing here verified.
func TestIDTokenEmitsStoredPhoneVerification(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_sso", Name: "enterprise-sso", Strategy: "oidc"}},
		Users: []config.User{{
			ID: "waad|sso", Email: "someone@example.com", Phone: "+12145551234",
			PhoneVerified: false,
			Identities:    []config.UserIdentity{{Connection: "enterprise-sso"}},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	code := srv.IssueAuthCode("waad|sso", "openid profile", "", "test_client")
	resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"test_client"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if claims := claimsOf(t, srv, tokens.IDToken); claims["phone_number_verified"] != false {
		t.Fatalf("phone_number_verified = %v, want the stored false", claims["phone_number_verified"])
	}
}

// A property the mock does not model would otherwise be accepted and dropped,
// and the caller would read back a user missing what it sent.
func TestCreateUserRejectsUnknownFields(t *testing.T) {
	_, ts := passwordlessMgmt(t, nil)

	resp, err := http.Post(ts.URL+"/api/v2/users", "application/json",
		strings.NewReader(`{"email":"someone@example.com","connection":"email","nickname_typo":"x"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unmodelled field", resp.StatusCode)
	}
}

// The normal passwordless flow omits the connection parameter, so an
// enterprise subject that happens to sort first must not be issued the token
// and then marked verified by a code it never received.
func TestDefaultOTPLoginPrefersThePasswordlessIdentity(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer: "https://auth.test/",
		Connections: []config.Connection{
			{ID: "con_email", Name: "email", Strategy: "email"},
			{ID: "con_sso", Name: "enterprise-sso", Strategy: "oidc"},
		},
		Users: []config.User{
			{ID: "aaa-waad|sso", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "enterprise-sso"}}},
			{ID: "zzz-email|pwdless", Email: "someone@example.com",
				Identities: []config.UserIdentity{{Connection: "email"}}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got := srv.findUserForConnection("someone@example.com", "")
	if got == nil || got.ID != "zzz-email|pwdless" {
		t.Fatalf("resolved %v, want the passwordless identity", got)
	}
}

// The SDK's marshaler sends user_id whenever the caller set management.User.ID,
// and the strict decode would otherwise refuse a valid request.
func TestCreateUserHonorsASuppliedUserID(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	user := &management.User{
		ID:         auth0.String("chosen"),
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("email"),
	}
	if err := mgmt.User.Create(context.Background(), user); err != nil {
		t.Fatalf("User.Create: %v", err)
	}
	// Auth0 treats the supplied value as the provider subject and prefixes the
	// root id itself, so "chosen" reads back as "email|chosen".
	if user.GetID() != "email|chosen" {
		t.Fatalf("id = %q, want the provider-prefixed form", user.GetID())
	}
	if user.Identities[0].GetUserID() != "chosen" {
		t.Fatalf("identity subject = %q, want the supplied one", user.Identities[0].GetUserID())
	}
}

// Phone attributes belong to an SMS user; storing them on an email connection
// returns a mixed profile Auth0 refuses to create.
func TestCreateUserRejectsPhoneOnAnEmailConnection(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	err := mgmt.User.Create(context.Background(), &management.User{
		Email:       auth0.String("someone@example.com"),
		Connection:  auth0.String("email"),
		PhoneNumber: auth0.String("+12145551234"),
	})
	if err == nil {
		t.Fatal("created a mixed email/phone profile")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got)
	}
}

// Memberships stay keyed to the id, so overwriting a profile would hand the new
// user the previous one's organization access.
func TestCreateUserRejectsATakenUserID(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, []config.User{{
		ID:         "email|taken",
		Email:      "first@example.com",
		Identities: []config.UserIdentity{{Connection: "email"}},
	}})

	err := mgmt.User.Create(context.Background(), &management.User{
		ID:         auth0.String("taken"),
		Email:      auth0.String("second@example.com"),
		Connection: auth0.String("email"),
	})
	if err == nil {
		t.Fatal("overwrote an existing account by id")
	}
	if got := statusOf(t, err); got != http.StatusConflict {
		t.Fatalf("status = %d, want 409", got)
	}
}

// Auth0 normalizes a profile name rather than storing an empty one; without it
// every token for a pre-admitted member carries "name": "".
func TestCreateUserDefaultsTheName(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	user := &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("email"),
	}
	if err := mgmt.User.Create(context.Background(), user); err != nil {
		t.Fatalf("User.Create: %v", err)
	}
	if user.GetName() != "someone@example.com" {
		t.Fatalf("name = %q, want the identifier", user.GetName())
	}
}

// A value bool cannot tell false from omitted, so an unsupported field would
// receive a 201 and be dropped.
func TestCreateUserRejectsPhoneVerifiedFalseOnEmail(t *testing.T) {
	_, ts := passwordlessMgmt(t, nil)

	resp, err := http.Post(ts.URL+"/api/v2/users", "application/json",
		strings.NewReader(`{"email":"someone@example.com","connection":"email","phone_verified":false}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a phone attribute on an email connection", resp.StatusCode)
	}
}

// An invitation carries a role and an organization membership, so resolving it
// to another connection's user would hand both to someone it was not for.
func TestInvitationLookupWillNotCrossConnections(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer: "https://auth.test/",
		Connections: []config.Connection{
			{ID: "con_email", Name: "email", Strategy: "email"},
			{ID: "con_sso", Name: "enterprise-sso", Strategy: "oidc"},
		},
		Users: []config.User{{ID: "email|pwdless", Email: "someone@example.com",
			Identities: []config.UserIdentity{{Connection: "email"}}}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := srv.findUserStrictlyForConnectionLocked("someone@example.com", "enterprise-sso"); got != nil {
		t.Fatalf("redemption resolved %v, want nil rather than another connection's user", got.ID)
	}
	// The login path stays looser on purpose.
	if got := srv.findUserForConnection("someone@example.com", "enterprise-sso"); got == nil {
		t.Fatal("login lookup should still fall back for a federated connection")
	}
}

// Auto-creation infers a passwordless shape from the identifier, so a federated
// connection would otherwise get an email/sms provider and an address nothing
// verified.
func TestAutoCreateKeepsAFederatedProfileCoherent(t *testing.T) {
	srv, err := New(&config.Config{
		Issuer:      "https://auth.test/",
		Connections: []config.Connection{{ID: "con_sso", Name: "enterprise-sso", Strategy: "oidc"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	user := srv.autoCreateUserForConnection("someone@example.com", "enterprise-sso")
	if user == nil {
		t.Fatal("no user created")
	}
	if user.Identities[0].Provider != "oidc" {
		t.Fatalf("provider = %q, want the connection's strategy", user.Identities[0].Provider)
	}
	if user.EmailVerified {
		t.Fatal("claimed the address verified though the IdP owns that and nothing checked it")
	}
}

// Auth0 returns these on create and management.User models them.
func TestCreateUserSetsTimestamps(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, nil)

	user := &management.User{
		Email:      auth0.String("someone@example.com"),
		Connection: auth0.String("email"),
	}
	if err := mgmt.User.Create(context.Background(), user); err != nil {
		t.Fatalf("User.Create: %v", err)
	}
	if user.GetCreatedAt().IsZero() || user.GetUpdatedAt().IsZero() {
		t.Fatalf("timestamps missing: created=%v updated=%v", user.GetCreatedAt(), user.GetUpdatedAt())
	}
}

// An SDK request explicitly setting false must read back as false, not vanish.
func TestPhoneVerifiedFalseRoundTrips(t *testing.T) {
	mgmt, _ := passwordlessMgmt(t, []config.User{{
		ID: "sms|member", Phone: "+12145551234", PhoneVerified: false,
		Identities: []config.UserIdentity{{Connection: "sms"}},
	}})

	read, err := mgmt.User.Read(context.Background(), "sms|member")
	if err != nil {
		t.Fatalf("User.Read: %v", err)
	}
	if read.PhoneVerified == nil {
		t.Fatal("phone_verified was omitted, so an explicit false is indistinguishable from unset")
	}
	if read.GetPhoneVerified() {
		t.Fatalf("phone_verified = true, want the stored false")
	}
}
