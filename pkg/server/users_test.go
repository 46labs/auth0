package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"

	"github.com/46labs/auth0/pkg/config"
)

// ssoConnection creates the oidc connection acme-oidc.
func ssoConnection(t *testing.T, m *management.Management) *management.Connection {
	t.Helper()
	c := &management.Connection{Name: auth0.String("acme-oidc"), Strategy: auth0.String("oidc")}
	if err := m.Connection.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

// ssoInOrg is ssoConnection enabled on org_test with auto-membership.
func ssoInOrg(t *testing.T, m *management.Management) *management.Connection {
	t.Helper()
	c := ssoConnection(t, m)
	if err := m.Organization.AddConnection(context.Background(), "org_test", &management.OrganizationConnection{
		ConnectionID: c.ID, AssignMembershipOnLogin: auth0.Bool(true),
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// registerTestClient registers the client loginToOrgVia signs in as, so its
// connection enablement is checked.
func registerTestClient(srv *Server) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.clients["test_client"] = &config.Client{ClientID: "test_client", Name: "spa"}
}

func createEmailUser(t *testing.T, m *management.Management, email string) *management.User {
	t.Helper()
	u := &management.User{
		Email: auth0.String(email), Connection: auth0.String("email"),
		EmailVerified: auth0.Bool(false), VerifyEmail: auth0.Bool(false),
	}
	if err := m.User.Create(context.Background(), u); err != nil {
		t.Fatalf("Create user: %v", err)
	}
	return u
}

func TestCreatePasswordlessUser(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()

	u := createEmailUser(t, m, "Pat@Acme.com")
	if !strings.HasPrefix(u.GetID(), "email|") || u.GetEmail() != "pat@acme.com" || u.GetEmailVerified() || u.UpdatedAt == nil || u.CreatedAt == nil {
		t.Fatalf("created = %+v", u)
	}
	if len(u.Identities) != 1 || u.Identities[0].GetProvider() != "email" || "email|"+u.Identities[0].GetUserID() != u.GetID() {
		t.Fatalf("identities = %+v", u.Identities)
	}

	// The same address on the same connection is one user.
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("pat@acme.com"), Connection: auth0.String("email")}), http.StatusConflict)
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("a@b.c"), Connection: auth0.String("missing")}), http.StatusBadRequest)
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("a@b.c")}), http.StatusBadRequest)
	wantStatus(t, m.User.Create(ctx, &management.User{Connection: auth0.String("email")}), http.StatusBadRequest)
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("a@b.c"), Connection: auth0.String("email"), Username: auth0.String("a")}), http.StatusBadRequest)
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("a@b.c"), Connection: auth0.String("email"), PhoneNumber: auth0.String("+14155550000")}), http.StatusBadRequest)
	for _, bad := range []string{"(214) 555-1234", "14155550000", ""} {
		wantStatus(t, m.User.Create(ctx, &management.User{PhoneNumber: auth0.String(bad), Connection: auth0.String("sms")}), http.StatusBadRequest)
	}
	if err := m.User.Create(ctx, &management.User{PhoneNumber: auth0.String("+14155550000"), Email: auth0.String("shared@acme.com"), Connection: auth0.String("sms")}); err != nil {
		t.Fatalf("E.164 sms user: %v", err)
	}
	// An sms user is keyed by its phone; a shared profile email is no conflict.
	if err := m.User.Create(ctx, &management.User{PhoneNumber: auth0.String("+14155550001"), Email: auth0.String("shared@acme.com"), Connection: auth0.String("sms")}); err != nil {
		t.Fatalf("second sms user: %v", err)
	}
	wantStatus(t, m.User.Create(ctx, &management.User{PhoneNumber: auth0.String("+14155550000"), Connection: auth0.String("sms")}), http.StatusConflict)
	for _, bad := range []string{"not-an-email", "@", "Pat <pat@acme.com>"} {
		wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String(bad), Connection: auth0.String("email")}), http.StatusBadRequest)
	}

	// logins_count is absent until a sign-in, as Auth0 records it. Raw decode:
	// the SDK's pointer hides absent versus zero.
	var raw map[string]any
	if err := m.Request(ctx, http.MethodGet, m.URI("users", u.GetID()), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["logins_count"]; ok {
		t.Fatalf("logins_count present before a sign-in: %v", raw)
	}

	ssoConnection(t, m)
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("a@b.c"), Connection: auth0.String("acme-oidc")}), http.StatusBadRequest)
}

func TestListUsersByEmail(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	createEmailUser(t, m, "pat@acme.com")

	users, err := m.User.ListByEmail(ctx, "pat@acme.com")
	if err != nil || len(users) != 1 || users[0].GetEmail() != "pat@acme.com" {
		t.Fatalf("users = %+v, err %v", users, err)
	}
	// Exact, as Auth0's: it lowercases on store, not on search.
	if users, err = m.User.ListByEmail(ctx, "PAT@acme.com"); err != nil || len(users) != 0 {
		t.Fatalf("mixed-case lookup = %+v, err %v", users, err)
	}
	users, err = m.User.ListByEmail(ctx, "nobody@acme.com")
	if err != nil || len(users) != 0 {
		t.Fatalf("users = %+v, err %v", users, err)
	}
}

func TestConnectionListFiltersByNameAndStrategy(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()

	list, err := m.Connection.List(ctx, management.Parameter("strategy", "email"), management.IncludeTotals(true))
	if err != nil || len(list.Connections) != 1 || list.Connections[0].GetName() != "email" {
		t.Fatalf("by strategy = %+v, err %v", list, err)
	}
	// A substring, as Auth0 matches it.
	list, err = m.Connection.List(ctx, management.Parameter("name", "ms"), management.IncludeTotals(true))
	if err != nil || len(list.Connections) != 1 || list.Connections[0].GetStrategy() != "sms" {
		t.Fatalf("by name = %+v, err %v", list, err)
	}
	wantStatus(t, m.Connection.Create(ctx, &management.Connection{Name: auth0.String("sms"), Strategy: auth0.String("sms")}), http.StatusConflict)
}

// The flow PEE drives: admit an address, the person signs in through SSO and
// with a code, an admin links the two, and either sign-in lands on one user.
func TestLinkPasswordlessIntoSSOUser(t *testing.T) {
	srv, m, base := ssoMgmt(t)
	ctx := context.Background()

	ssoInOrg(t, m)

	secondary := createEmailUser(t, m, "pat@acme.com")
	if err := m.Organization.AddMembers(ctx, "org_test", []string{secondary.GetID()}); err != nil {
		t.Fatal(err)
	}

	// A code sign-in proves the address.
	if tokens, status, msg := loginToOrgVia(t, base, "pat@acme.com", "org_test", "openid", "email"); tokens == nil {
		t.Fatalf("passwordless login: %d %s", status, msg)
	}
	got, err := m.User.Read(ctx, secondary.GetID())
	if err != nil || !got.GetEmailVerified() || got.GetLoginsCount() != 1 {
		t.Fatalf("after code login = %+v, err %v", got, err)
	}

	// The first SSO sign-in provisions a separate user under the connection.
	tokens, status, msg := loginToOrgVia(t, base, "pat@acme.com", "org_test", "openid", "acme-oidc")
	if tokens == nil {
		t.Fatalf("sso login: %d %s", status, msg)
	}
	primaryID, _ := claimsOf(t, srv, tokens.AccessToken)["sub"].(string)
	if !strings.HasPrefix(primaryID, "oidc|acme-oidc|") {
		t.Fatalf("sso sub = %q", primaryID)
	}
	primary, err := m.User.Read(ctx, primaryID)
	if err != nil || primary.GetLoginsCount() != 1 || primary.Identities[0].GetUserID() != strings.TrimPrefix(primaryID, "oidc|") {
		t.Fatalf("sso user = %+v, err %v", primary, err)
	}

	ids, err := m.User.Link(ctx, primaryID, &management.UserIdentityLink{
		Provider: auth0.String("email"), UserID: auth0.String(secondary.Identities[0].GetUserID()),
	})
	if err != nil || len(ids) != 2 || ids[1].GetProvider() != "email" {
		t.Fatalf("link = %+v, err %v", ids, err)
	}
	if email, _ := (*ids[1].ProfileData)["email"].(string); email != "pat@acme.com" {
		t.Fatalf("profileData = %+v", ids[1].ProfileData)
	}
	if ids[0].ProfileData == nil {
		t.Fatal("the primary identity carries no profileData")
	}

	// Auth0 deletes the secondary, membership included.
	_, err = m.User.Read(ctx, secondary.GetID())
	wantStatus(t, err, http.StatusNotFound)
	members, err := m.Organization.Members(ctx, "org_test")
	if err != nil || slices.ContainsFunc(members.Members, func(u management.OrganizationMember) bool { return u.GetUserID() == secondary.GetID() }) {
		t.Fatalf("secondary still a member: %+v, err %v", members, err)
	}

	// Actions see the connection signed in through, not the primary's.
	mgmt{t, base}.deployBound("conn-claim",
		`exports.onExecutePostLogin = async (event, api) => { api.accessToken.setCustomClaim("https://x/conn", event.connection.name) }`)

	// A code sign-in now lands on the primary.
	tokens, status, msg = loginToOrgVia(t, base, "pat@acme.com", "org_test", "openid", "email")
	if tokens == nil {
		t.Fatalf("passwordless login after link: %d %s", status, msg)
	}
	claims := claimsOf(t, srv, tokens.AccessToken)
	if claims["sub"] != primaryID || claims["https://x/conn"] != "email" {
		t.Fatalf("after link: sub %v, connection %v; want %s through email", claims["sub"], claims["https://x/conn"], primaryID)
	}
	// Unnamed, the connection is the identity the code matched.
	tokens, status, msg = loginToOrgVia(t, base, "pat@acme.com", "", "openid", "")
	if tokens == nil {
		t.Fatalf("unnamed passwordless login: %d %s", status, msg)
	}
	if c := claimsOf(t, srv, tokens.AccessToken)["https://x/conn"]; c != "email" {
		t.Fatalf("unnamed login connection = %v, want email", c)
	}
}

func TestLinkRefusesWhatAuth0Refuses(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	u := createEmailUser(t, m, "pat@acme.com")
	other := createEmailUser(t, m, "sam@acme.com")

	_, err := m.User.Link(ctx, "email|missing", &management.UserIdentityLink{Provider: auth0.String("email"), UserID: other.Identities[0].UserID})
	wantStatus(t, err, http.StatusNotFound)
	_, err = m.User.Link(ctx, u.GetID(), &management.UserIdentityLink{Provider: auth0.String("email"), UserID: u.Identities[0].UserID})
	wantStatus(t, err, http.StatusBadRequest)
	_, err = m.User.Link(ctx, u.GetID(), &management.UserIdentityLink{Provider: auth0.String("email"), UserID: auth0.String("missing")})
	wantStatus(t, err, http.StatusBadRequest)
	_, err = m.User.Link(ctx, u.GetID(), &management.UserIdentityLink{LinkWith: auth0.String("token")})
	wantStatus(t, err, http.StatusBadRequest)
}

// The SDK's own Link test passes the secondary's full user id.
func TestLinkAcceptsTheFullUserID(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	primary := createEmailUser(t, m, "pat@acme.com")
	secondary := createEmailUser(t, m, "sam@acme.com")

	ids, err := m.User.Link(ctx, primary.GetID(), &management.UserIdentityLink{Provider: auth0.String("email"), UserID: secondary.ID})
	if err != nil || len(ids) != 2 || "email|"+ids[1].GetUserID() != secondary.GetID() {
		t.Fatalf("link = %+v, err %v", ids, err)
	}
	// The linked address is taken on its connection, though only the
	// identity's profile names it.
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("sam@acme.com"), Connection: auth0.String("email")}), http.StatusConflict)
}

// A configured user's id need not spell its main identity; the link finds it
// by the identity.
func TestLinkFindsTheSecondaryByItsIdentity(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	primary := createEmailUser(t, m, "pat@acme.com")

	// test_user_2 is configured with an email identity whose id is its own.
	ids, err := m.User.Link(ctx, primary.GetID(), &management.UserIdentityLink{Provider: auth0.String("email"), UserID: auth0.String("test_user_2")})
	if err != nil || len(ids) != 2 {
		t.Fatalf("link = %+v, err %v", ids, err)
	}
	_, err = m.User.Read(ctx, "test_user_2")
	wantStatus(t, err, http.StatusNotFound)
}

// A code sign-in through the email connection signs in only that connection's
// users: an SSO user with the address is someone else until linked.
func TestPasswordlessLoginIgnoresAnEnterpriseUserWithTheAddress(t *testing.T) {
	srv, m, base := ssoMgmt(t)

	ssoInOrg(t, m)
	tokens, status, msg := loginToOrgVia(t, base, "pat@acme.com", "org_test", "openid", "acme-oidc")
	if tokens == nil {
		t.Fatalf("sso login: %d %s", status, msg)
	}
	ssoSub := claimsOf(t, srv, tokens.AccessToken)["sub"]

	// The SSO sign-in does not touch email_verified, which the IdP owns.
	srv.mu.Lock()
	srv.users[ssoSub.(string)].EmailVerified = false
	srv.mu.Unlock()
	if tokens, _, _ = loginToOrgVia(t, base, "pat@acme.com", "org_test", "openid", "acme-oidc"); tokens == nil {
		t.Fatal("second sso login refused")
	}
	if u := srv.getUserByID(ssoSub.(string)); u.EmailVerified || u.LoginsCount != 2 {
		t.Fatalf("sso user after login = %+v", u)
	}

	// Not a member through email, so the org refuses; what matters is who
	// signed in, which the refusal does not reveal, so sign in without an org.
	tokens, status, msg = loginToOrgVia(t, base, "pat@acme.com", "", "openid", "email")
	if tokens == nil {
		t.Fatalf("passwordless login: %d %s", status, msg)
	}
	if sub, _ := claimsOf(t, srv, tokens.AccessToken)["sub"].(string); sub == ssoSub || !strings.HasPrefix(sub, "email|") {
		t.Fatalf("passwordless sub = %v, sso sub = %v", sub, ssoSub)
	}
}

// A named passwordless connection takes only its own kind of identifier, and
// the address it provisions is stored in lower case, as Auth0 stores it.
func TestPasswordlessLoginScopesToItsConnection(t *testing.T) {
	_, m, base := ssoMgmt(t)
	ctx := context.Background()

	if tokens, _, _ := loginToOrgVia(t, base, "pat@acme.com", "", "openid", "sms"); tokens != nil {
		t.Fatal("an email signed in through the sms connection")
	}
	if tokens, status, msg := loginToOrgVia(t, base, "Pat@Acme.com", "", "openid", "email"); tokens == nil {
		t.Fatalf("login: %d %s", status, msg)
	}
	users, err := m.User.ListByEmail(ctx, "pat@acme.com")
	if err != nil || len(users) != 1 || users[0].CreatedAt == nil || users[0].Identities[0].GetConnection() != "email" {
		t.Fatalf("users = %+v, err %v", users, err)
	}
}

// A configured user listing no identities has no provenance to rule out, so a
// named passwordless connection signs it in rather than creating a duplicate.
func TestNamedPasswordlessLoginReusesAConfiguredUserWithoutIdentities(t *testing.T) {
	srv, _, base := ssoMgmt(t)
	srv.mu.Lock()
	srv.users["auth0|seeded"] = &config.User{ID: "auth0|seeded", Email: "seeded@acme.com"}
	n := len(srv.users)
	srv.mu.Unlock()

	tokens, status, msg := loginToOrgVia(t, base, "seeded@acme.com", "", "openid", "email")
	if tokens == nil {
		t.Fatalf("login: %d %s", status, msg)
	}
	if sub := claimsOf(t, srv, tokens.AccessToken)["sub"]; sub != "auth0|seeded" {
		t.Fatalf("sub = %v", sub)
	}
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if len(srv.users) != n {
		t.Fatalf("users = %d, want %d", len(srv.users), n)
	}
}

// An invitation through an enterprise connection provisions that connection's
// user, so the invitee's later SSO sign-in is the same account.
func TestEnterpriseInvitationProvisionsTheEnterpriseUser(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	// Not pinned by the invitation: the connection named at sign-in decides.
	inv := f.invitation("lee@example.test")
	if err := f.m.Organization.CreateInvitation(context.Background(), f.orgID, inv); err != nil {
		t.Fatal(err)
	}
	user, _, err := f.srv.redeemInvitation(invitationTicket{OrgID: f.orgID, TicketID: inv.GetTicketID(), ClientID: f.clientID, ConnectionName: "enterprise-sso"}, "lee@example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(user.ID, "oidc|enterprise-sso|") || user.Identities[0].Connection != "enterprise-sso" {
		t.Fatalf("invitee = %+v", user)
	}
	tokens, status, msg := loginToOrgVia(t, f.ts.URL, "lee@example.test", f.orgID, "openid", "enterprise-sso")
	if tokens == nil {
		t.Fatalf("sso login: %d %s", status, msg)
	}
	if sub := claimsOf(t, f.srv, tokens.AccessToken)["sub"]; sub != user.ID {
		t.Fatalf("sso sub = %v, want %s", sub, user.ID)
	}
}

// The main identity follows the user's live profile, not the copy a link
// recorded, and an update advances updated_at.
func TestPrimaryIdentityFollowsTheLiveProfile(t *testing.T) {
	srv, m, _ := ssoMgmt(t)
	ctx := context.Background()
	primary := createEmailUser(t, m, "pat@acme.com")
	secondary := createEmailUser(t, m, "sam@acme.com")
	if _, err := m.User.Link(ctx, primary.GetID(), &management.UserIdentityLink{Provider: auth0.String("email"), UserID: secondary.ID}); err != nil {
		t.Fatal(err)
	}
	// Backdated rather than waited on, so the advance is visible.
	const old = "2020-01-01T00:00:00.000Z"
	srv.mu.Lock()
	srv.users[primary.GetID()].UpdatedAt = old
	srv.mu.Unlock()

	if err := m.User.Update(ctx, primary.GetID(), &management.User{Email: auth0.String("pat.new@acme.com")}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("pat.new@acme.com"), Connection: auth0.String("email")}), http.StatusConflict)

	// A later link refreshes the main identity's profile.
	third := createEmailUser(t, m, "kim@acme.com")
	ids, err := m.User.Link(ctx, primary.GetID(), &management.UserIdentityLink{Provider: auth0.String("email"), UserID: third.ID})
	if err != nil || (*ids[0].ProfileData)["email"] != "pat.new@acme.com" {
		t.Fatalf("primary profileData = %+v, err %v", ids[0].ProfileData, err)
	}

	after, err := m.User.Read(ctx, primary.GetID())
	if err != nil || after.UpdatedAt == nil || after.UpdatedAt.Format("2006-01-02T15:04:05.000Z") == old {
		t.Fatalf("updated_at = %v, err %v", after.UpdatedAt, err)
	}
}

// An unpinned invitation redeemed with a code goes to the passwordless
// account, not an SSO account sharing the address, and verifies it.
func TestUnpinnedInvitationRedeemsThePasswordlessAccount(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	if tokens, status, msg := loginToOrgVia(t, f.ts.URL, "lee@example.test", "", "openid", "enterprise-sso"); tokens == nil {
		t.Fatalf("sso login: %d %s", status, msg)
	}
	pw := createEmailUser(t, f.m, "lee@example.test")

	inv := f.invitation("lee@example.test")
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatal(err)
	}
	if tokens, status, body := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), "lee@example.test", f.clientID); tokens == nil {
		t.Fatalf("redeem: %d %s", status, body)
	}
	got, err := f.m.User.Read(ctx, pw.GetID())
	if err != nil || !got.GetEmailVerified() {
		t.Fatalf("passwordless user = %+v, err %v", got, err)
	}
	members, err := f.m.Organization.Members(ctx, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	for _, mem := range members.Members {
		if mem.GetEmail() == "lee@example.test" && mem.GetUserID() != pw.GetID() {
			t.Fatalf("invitation went to %s, want %s", mem.GetUserID(), pw.GetID())
		}
	}
}

// A code sign-in with no connection named provisions on the tenant's own
// passwordless connection, whatever it is called.
func TestAutoProvisionUsesTheTenantsPasswordlessConnection(t *testing.T) {
	srv, m, base := ssoMgmt(t)
	ctx := context.Background()
	srv.mu.Lock()
	srv.connections["con_email"].Name = "passwordless-email"
	srv.mu.Unlock()

	if tokens, status, msg := loginToOrgVia(t, base, "new@acme.com", "", "openid", ""); tokens == nil {
		t.Fatalf("login: %d %s", status, msg)
	}
	users, err := m.User.ListByEmail(ctx, "new@acme.com")
	if err != nil || len(users) != 1 || users[0].Identities[0].GetConnection() != "passwordless-email" {
		t.Fatalf("users = %+v, err %v", users, err)
	}
}

func TestLinkRefusesAPrimaryWithoutIdentities(t *testing.T) {
	srv, m, _ := ssoMgmt(t)
	srv.mu.Lock()
	srv.users["auth0|bare"] = &config.User{ID: "auth0|bare", Email: "bare@acme.com"}
	srv.mu.Unlock()
	other := createEmailUser(t, m, "sam@acme.com")
	_, err := m.User.Link(context.Background(), "auth0|bare", &management.UserIdentityLink{Provider: auth0.String("email"), UserID: other.ID})
	wantStatus(t, err, http.StatusBadRequest)
}

func TestCreateSMSUserKeepsPhoneVerified(t *testing.T) {
	_, m, _ := ssoMgmt(t)
	ctx := context.Background()
	u := &management.User{PhoneNumber: auth0.String("+14155550002"), PhoneVerified: auth0.Bool(true), Connection: auth0.String("sms")}
	if err := m.User.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := m.User.Read(ctx, u.GetID())
	if err != nil || !got.GetPhoneVerified() {
		t.Fatalf("user = %+v, err %v", got, err)
	}
	wantStatus(t, m.User.Create(ctx, &management.User{Email: auth0.String("x@acme.com"), PhoneVerified: auth0.Bool(true), Connection: auth0.String("email")}), http.StatusBadRequest)
}

// An sms user reports phone_verified false until a code proves the number,
// and a link carries the state in the identity's profile.
func TestSMSVerificationRoundTrips(t *testing.T) {
	_, m, base := ssoMgmt(t)
	ctx := context.Background()

	u := &management.User{PhoneNumber: auth0.String("+14155550003"), Connection: auth0.String("sms")}
	if err := m.User.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if u.PhoneVerified == nil || u.GetPhoneVerified() {
		t.Fatalf("created phone_verified = %v, want false", u.PhoneVerified)
	}
	primary := createEmailUser(t, m, "pat@acme.com")
	ids, err := m.User.Link(ctx, primary.GetID(), &management.UserIdentityLink{Provider: auth0.String("sms"), UserID: u.ID})
	if err != nil {
		t.Fatal(err)
	}
	p := *ids[1].ProfileData
	if _, hasEmail := p["email"]; hasEmail || p["phone_verified"] != false {
		t.Fatalf("linked sms profile = %v", p)
	}

	if tokens, status, msg := loginToOrgVia(t, base, "+14155550003", "", "openid", "sms"); tokens == nil {
		t.Fatalf("sms login: %d %s", status, msg)
	}
	got, err := m.User.Read(ctx, primary.GetID())
	if err != nil || (*got.Identities[1].ProfileData)["phone_verified"] != true {
		t.Fatalf("after sms login = %+v, err %v", got.Identities, err)
	}
}

// A named connection signs in only when it exists, is enabled for the calling
// client, and is enabled on the organization, as Auth0 requires.
func TestLoginRefusesAConnectionAuth0WouldRefuse(t *testing.T) {
	srv, m, base := ssoMgmt(t)
	ctx := context.Background()
	registerTestClient(srv)

	srv.mu.RLock()
	before := len(srv.users)
	srv.mu.RUnlock()
	if tokens, _, msg := loginToOrgVia(t, base, "pat@acme.com", "", "openid", "no-such-connection"); tokens != nil || !strings.Contains(msg, "does not exist") {
		t.Fatalf("unknown connection: tokens %v, %s", tokens, msg)
	}

	sso := ssoConnection(t, m)
	if tokens, _, msg := loginToOrgVia(t, base, "pat@acme.com", "", "openid", "acme-oidc"); tokens != nil || !strings.Contains(msg, "not enabled for this client") {
		t.Fatalf("not enabled for the client: tokens %v, %s", tokens, msg)
	}
	if err := m.Connection.UpdateEnabledClients(ctx, sso.GetID(), []management.ConnectionEnabledClient{
		{ClientID: auth0.String("test_client"), Status: auth0.Bool(true)},
	}); err != nil {
		t.Fatal(err)
	}
	if tokens, _, msg := loginToOrgVia(t, base, "pat@acme.com", "org_test", "openid", "acme-oidc"); tokens != nil || !strings.Contains(msg, "not enabled for the organization") {
		t.Fatalf("not on the organization: tokens %v, %s", tokens, msg)
	}
	// No refused attempt provisioned anyone.
	srv.mu.RLock()
	after := len(srv.users)
	srv.mu.RUnlock()
	if after != before {
		t.Fatalf("users %d -> %d across refused logins", before, after)
	}

	if err := m.Organization.AddConnection(ctx, "org_test", &management.OrganizationConnection{
		ConnectionID: sso.ID, AssignMembershipOnLogin: auth0.Bool(true),
	}); err != nil {
		t.Fatal(err)
	}
	if tokens, status, msg := loginToOrgVia(t, base, "pat@acme.com", "org_test", "openid", "acme-oidc"); tokens == nil {
		t.Fatalf("enabled everywhere: %d %s", status, msg)
	}
}

// An invitation through a connection not enabled for its registered client
// is refused before the ticket is spent.
func TestInvitationRefusesAConnectionNotEnabledForTheClient(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	if err := f.m.Connection.UpdateEnabledClients(ctx, f.connectionID, []management.ConnectionEnabledClient{
		{ClientID: auth0.String(f.clientID), Status: auth0.Bool(false)},
	}); err != nil {
		t.Fatal(err)
	}
	inv := f.invitation("lee@example.test")
	inv.ConnectionID = &f.connectionID
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatal(err)
	}
	if tokens, _, body := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), "lee@example.test", f.clientID); tokens != nil || !strings.Contains(body, "not enabled for this client") {
		t.Fatalf("redeemed through a disabled connection: tokens %v, %s", tokens, body)
	}
	if _, err := f.m.Organization.Invitation(ctx, f.orgID, inv.GetID()); err != nil {
		t.Fatalf("the refused attempt spent the invitation: %v", err)
	}
}

// loginUser refuses a named connection that is gone, rather than falling back
// to a passwordless sign-in.
func TestLoginUserRefusesAVanishedConnection(t *testing.T) {
	srv, _, _ := ssoMgmt(t)
	if u, conn, err := srv.loginUser("pat@acme.com", "deleted-sso", "", ""); u != nil || !errors.Is(err, errConnectionUnknown) {
		t.Fatalf("signed in %v through %q, err %v", u, conn, err)
	}
}

// A sign-in naming no connection is checked on the connection it resolves
// to, before anyone is provisioned.
func TestUnnamedLoginChecksTheResolvedConnection(t *testing.T) {
	srv, m, base := ssoMgmt(t)
	ctx := context.Background()
	registerTestClient(srv)
	srv.mu.RLock()
	n := len(srv.users)
	srv.mu.RUnlock()

	// The seeded email connection allows every client ("*"); disabling one
	// must take effect anyway.
	if err := m.Connection.UpdateEnabledClients(ctx, "con_email", []management.ConnectionEnabledClient{
		{ClientID: auth0.String("test_client"), Status: auth0.Bool(false)},
	}); err != nil {
		t.Fatal(err)
	}
	clients, err := m.Connection.ReadEnabledClients(ctx, "con_email")
	if err != nil || clients.Clients == nil || slices.ContainsFunc(*clients.Clients, func(c management.ConnectionEnabledClient) bool {
		return c.GetClientID() == "test_client" || c.GetClientID() == "*"
	}) {
		t.Fatalf("enabled clients after disable = %+v, err %v", clients, err)
	}

	if tokens, _, msg := loginToOrgVia(t, base, "new@acme.com", "", "openid", ""); tokens != nil || !strings.Contains(msg, "not enabled for this client") {
		t.Fatalf("unnamed login through a disabled connection: tokens %v, %s", tokens, msg)
	}
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if len(srv.users) != n {
		t.Fatalf("a refused login provisioned a user: %d -> %d", n, len(srv.users))
	}
}

// An invitation naming a connection that does not exist is refused and not
// spent, rather than redeemed as a passwordless sign-in.
func TestInvitationRefusesAnUnknownNamedConnection(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	inv := f.invitation("lee@example.test")
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.srv.redeemInvitation(invitationTicket{OrgID: f.orgID, TicketID: inv.GetTicketID(), ClientID: f.clientID, ConnectionName: "gone"}, "lee@example.test", time.Now())
	if !errors.Is(err, errConnectionUnknown) {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.m.Organization.Invitation(ctx, f.orgID, inv.GetID()); err != nil {
		t.Fatalf("the refused redemption spent the invitation: %v", err)
	}
}

// An email code for a user known only by an sms identity goes through the
// email connection, which is the one checked.
func TestProfileFallbackChecksTheCodesConnection(t *testing.T) {
	srv, m, base := ssoMgmt(t)
	ctx := context.Background()
	registerTestClient(srv)
	if err := m.Connection.UpdateEnabledClients(ctx, "con_email", []management.ConnectionEnabledClient{
		{ClientID: auth0.String("test_client"), Status: auth0.Bool(false)},
	}); err != nil {
		t.Fatal(err)
	}
	// test_user_1 has the address test@example.test but only an sms identity.
	if tokens, _, msg := loginToOrgVia(t, base, "test@example.test", "", "openid", ""); tokens != nil || !strings.Contains(msg, "not enabled for this client") {
		t.Fatalf("email code through a disabled email connection: tokens %v, %s", tokens, msg)
	}
}
