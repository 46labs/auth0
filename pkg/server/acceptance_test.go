package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/auth0/go-auth0/management"
	"github.com/golang-jwt/jwt/v5"
)

// noRedirectClient follows nothing, so the test can read Location headers.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// authorizeURLFromInvitation does what the SPA does at the login initiation
// endpoint: pull `invitation` and `organization` off the invitation URL and
// forward them to /authorize. The design is explicit that these ride on
// loginWithRedirect rather than the provider's authorizationParams, so that a
// consumed ticket is not replayed during silent renewal.
// clientID is the application the invitation was issued for: the invitation is
// bound to it, so the login has to run through that same client.
func authorizeURLFromInvitation(t *testing.T, baseURL, invURL, clientID string) string {
	t.Helper()

	u, err := url.Parse(invURL)
	if err != nil {
		t.Fatalf("invitation_url not parseable: %v", err)
	}
	q := u.Query()

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", testRedirectURI)
	params.Set("scope", "openid profile email")
	params.Set("invitation", q.Get("invitation"))
	params.Set("organization", q.Get("organization"))
	if conn := q.Get("connection"); conn != "" {
		params.Set("connection", conn)
	}
	return baseURL + "/authorize?" + params.Encode()
}

// acceptedTokens is the token response an accepted invitation yields.
type acceptedTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

// followInvitation drives the invitee's browser flow to completion: the
// login page, the verification code, then the token exchange. Returns the
// tokens, or the HTTP status and body of whichever step refused.
func followInvitation(t *testing.T, baseURL, invURL, identifier, clientID string) (*acceptedTokens, int, string) {
	t.Helper()

	client := noRedirectClient()

	resp, err := client.Get(authorizeURLFromInvitation(t, baseURL, invURL, clientID))
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// An invalid ticket is reported by redirecting to the app with an error.
	if resp.StatusCode == http.StatusFound {
		loc, _ := url.Parse(resp.Header.Get("Location"))
		return nil, resp.StatusCode, loc.Query().Get("error_description")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, string(body)
	}

	m := sessionIDRe.FindStringSubmatch(string(body))
	if len(m) < 2 {
		t.Fatalf("no session_id in login page")
	}

	resp2, err := client.PostForm(baseURL+"/authorize", url.Values{
		"session_id": {m[1]},
		"identifier": {identifier},
		"code":       {"123456"},
	})
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()

	if resp2.StatusCode != http.StatusFound {
		return nil, resp2.StatusCode, strings.TrimSpace(string(body2))
	}

	loc, err := url.Parse(resp2.Header.Get("Location"))
	if err != nil {
		t.Fatalf("bad Location: %v", err)
	}
	authCode := loc.Query().Get("code")
	if authCode == "" {
		return nil, resp2.StatusCode, "no code in redirect: " + resp2.Header.Get("Location")
	}

	resp3, err := client.PostForm(baseURL+"/oauth/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode},
		"client_id":    {clientID},
		"redirect_uri": {testRedirectURI},
	})
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		return nil, resp3.StatusCode, strings.TrimSpace(string(body3))
	}

	var tokens acceptedTokens
	if err := json.Unmarshal(body3, &tokens); err != nil {
		t.Fatalf("token response not JSON: %v (%s)", err, body3)
	}
	return &tokens, resp3.StatusCode, ""
}

// claimsOf verifies a token against the server's key and returns its claims.
func claimsOf(t *testing.T, srv *Server, token string) jwt.MapClaims {
	t.Helper()

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
		return &srv.privateKey.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("token did not verify: %v", err)
	}
	return claims
}

// createInvitation issues one through the SDK and returns it.
func (f *inviteFixture) createInvitation(t *testing.T, email string) *management.OrganizationInvitation {
	t.Helper()

	inv := f.invitation(email)
	if err := f.m.Organization.CreateInvitation(context.Background(), f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation(%s): %v", email, err)
	}
	return inv
}

// TestInvitationAcceptanceGrantsAdmin is the design's whole point: a platform
// admin invites an email address, the invitee completes the Auth0 flow, and
// comes out an admin of that organization.
func TestInvitationAcceptanceGrantsAdmin(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	const email = "first.admin@example.test"
	inv := f.createInvitation(t, email)

	tokens, status, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID)
	if tokens == nil {
		t.Fatalf("acceptance failed with %d: %s", status, msg)
	}

	// The user now exists.
	user := f.srv.findUser(email)
	if user == nil {
		t.Fatal("the invitee was not created")
	}

	// ...is a member of the organization...
	members := f.srv.GetOrgMembers(f.orgID)
	var member *config.OrganizationMember
	for i := range members {
		if members[i].UserID == user.ID {
			member = &members[i]
			break
		}
	}
	if member == nil {
		t.Fatalf("the invitee is not a member of %s", f.orgID)
	}

	// ...with the invitation's role...
	if member.Role != "admin" {
		t.Errorf("member role = %q, want admin", member.Role)
	}

	// ...recorded in the model pee reads...
	if got := user.AppMetadata.OrgRole(f.orgID); got != "admin" {
		t.Errorf("app_metadata.org_roles[%s] = %q, want admin", f.orgID, got)
	}

	// ...and the token says so.
	access := claimsOf(t, f.srv, tokens.AccessToken)
	if access["org_id"] != f.orgID {
		t.Errorf("access token org_id = %v, want %s", access["org_id"], f.orgID)
	}
	roleClaim := strings.TrimSuffix(f.srv.cfg.Issuer, "/") + "/role"
	if access[roleClaim] != "admin" {
		t.Errorf("access token %s = %v, want admin", roleClaim, access[roleClaim])
	}

	id := claimsOf(t, f.srv, tokens.IDToken)
	if id["org_id"] != f.orgID {
		t.Errorf("id token org_id = %v, want %s", id["org_id"], f.orgID)
	}
	if id["email"] != email {
		t.Errorf("id token email = %v, want %s", id["email"], email)
	}

	// The invitation is consumed, not merely marked.
	list, err := f.m.Organization.Invitations(context.Background(), f.orgID)
	if err != nil {
		t.Fatalf("Invitations: %v", err)
	}
	if len(list.OrganizationInvitations) != 0 {
		t.Errorf("invitation still pending after acceptance: %+v", list.OrganizationInvitations)
	}
}

// TestInvitationLoginPagePrefillsInvitee covers the pre-flight: the ticket is
// validated before the login page renders, and the invited address is filled
// in for the invitee.
func TestInvitationLoginPagePrefillsInvitee(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	const email = "prefill@example.test"
	inv := f.createInvitation(t, email)

	resp, err := noRedirectClient().Get(authorizeURLFromInvitation(t, f.ts.URL, inv.GetInvitationURL(), f.clientID))
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the login page, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), email) {
		t.Errorf("login page does not prefill the invited address %q", email)
	}
}

func TestInvitationAcceptanceRejections(t *testing.T) {
	t.Run("WrongInvitee", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()

		inv := f.createInvitation(t, "invited@example.test")

		// A leaked link must not onboard whoever opens it.
		tokens, _, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), "someone.else@example.test", f.clientID)
		if tokens != nil {
			t.Fatal("an invitation was accepted by the wrong address")
		}
		if !strings.Contains(msg, "different address") {
			t.Errorf("unexpected refusal: %s", msg)
		}

		// And it is still pending, not burned.
		list, err := f.m.Organization.Invitations(context.Background(), f.orgID)
		if err != nil {
			t.Fatalf("Invitations: %v", err)
		}
		if len(list.OrganizationInvitations) != 1 {
			t.Error("a failed acceptance consumed the invitation")
		}
	})

	t.Run("InviteeIsCaseInsensitive", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()

		inv := f.createInvitation(t, "MixedCase@example.test")

		tokens, status, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), "mixedcase@example.test", f.clientID)
		if tokens == nil {
			t.Fatalf("email comparison should be case insensitive; got %d: %s", status, msg)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()

		inv := f.createInvitation(t, "expired@example.test")

		f.srv.mu.Lock()
		for i := range f.srv.invitations[f.orgID] {
			f.srv.invitations[f.orgID][i].ExpiresAt = time.Now().Add(-time.Second)
		}
		f.srv.mu.Unlock()

		tokens, _, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), "expired@example.test", f.clientID)
		if tokens != nil {
			t.Fatal("an expired invitation was accepted")
		}
		if !strings.Contains(msg, "not valid") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})

	t.Run("Revoked", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()

		inv := f.createInvitation(t, "revoked@example.test")
		if err := f.m.Organization.DeleteInvitation(context.Background(), f.orgID, inv.GetID()); err != nil {
			t.Fatalf("DeleteInvitation: %v", err)
		}

		tokens, _, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), "revoked@example.test", f.clientID)
		if tokens != nil {
			t.Fatal("a revoked invitation was accepted")
		}
		if !strings.Contains(msg, "not valid") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})

	t.Run("UnknownTicket", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()

		bogus := "https://app.example.test/login?invitation=tkt_nope&organization=" + f.orgID
		tokens, _, msg := followInvitation(t, f.ts.URL, bogus, "nobody@example.test", f.clientID)
		if tokens != nil {
			t.Fatal("a bogus ticket was accepted")
		}
		if !strings.Contains(msg, "not valid") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})

	t.Run("TicketWithoutOrganization", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()

		inv := f.createInvitation(t, "noorg@example.test")

		// Drop the organization parameter the SPA is supposed to forward.
		stripped := strings.Split(inv.GetInvitationURL(), "&organization=")[0]
		tokens, _, msg := followInvitation(t, f.ts.URL, stripped, "noorg@example.test", f.clientID)
		if tokens != nil {
			t.Fatal("a ticket without its organization was accepted")
		}
		if !strings.Contains(msg, "not valid") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})

	t.Run("TicketFromAnotherOrganization", func(t *testing.T) {
		f, cleanup := newInviteFixture(t)
		defer cleanup()

		other := "other-org"
		otherOrg := &management.Organization{Name: &other}
		if err := f.m.Organization.Create(context.Background(), otherOrg); err != nil {
			t.Fatalf("Organization.Create: %v", err)
		}

		inv := f.createInvitation(t, "crossorg@example.test")
		crossed := strings.Replace(inv.GetInvitationURL(),
			"organization="+f.orgID, "organization="+otherOrg.GetID(), 1)

		tokens, _, msg := followInvitation(t, f.ts.URL, crossed, "crossorg@example.test", f.clientID)
		if tokens != nil {
			t.Fatal("a ticket was accepted against a different organization")
		}
		if !strings.Contains(msg, "not valid") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})
}

// TestInvitationForcedConnectionIsEnforced covers connection_id on the
// invitation. The link's shape is fixed by the spec and carries no
// connection, so an omitted one falls back to the ticket's; an explicit
// mismatch is refused. Auth0's `connection` parameter is a name.
func TestInvitationForcedConnectionIsEnforced(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	newInvite := func(t *testing.T, email string) *management.OrganizationInvitation {
		t.Helper()
		inv := f.invitation(email)
		inv.ConnectionID = &f.connectionID
		if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		return inv
	}

	t.Run("LinkCarriesNoConnection", func(t *testing.T) {
		inv := newInvite(t, "forced-a@example.test")
		if got := mustQuery(t, inv.GetInvitationURL()).Get("connection"); got != "" {
			t.Errorf("invitation_url should not carry a connection, got %q", got)
		}
		if tokens, st, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(),
			"forced-a@example.test", f.clientID); tokens == nil {
			t.Fatalf("an omitted connection should fall back to the ticket: %d %s", st, msg)
		}
	})

	t.Run("MatchingConnectionNameAccepted", func(t *testing.T) {
		inv := newInvite(t, "forced-b@example.test")
		// The fixture's connection is named enterprise-sso.
		link := inv.GetInvitationURL() + "&connection=enterprise-sso"
		if tokens, st, msg := followInvitation(t, f.ts.URL, link,
			"forced-b@example.test", f.clientID); tokens == nil {
			t.Fatalf("the matching connection name should be accepted: %d %s", st, msg)
		}
	})

	t.Run("MismatchedConnectionRefused", func(t *testing.T) {
		inv := newInvite(t, "forced-c@example.test")
		link := inv.GetInvitationURL() + "&connection=email"
		tokens, _, msg := followInvitation(t, f.ts.URL, link, "forced-c@example.test", f.clientID)
		if tokens != nil {
			t.Error("an invitation was redeemed through the wrong connection")
		} else if !strings.Contains(msg, "different connection") {
			t.Errorf("unexpected refusal: %s", msg)
		}
	})
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Query()
}

// TestInvitationIsSingleUse covers the replay half of requirement 4: once
// accepted, the same link must not work again — for the original invitee or
// anyone else.
func TestInvitationIsSingleUse(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	const email = "once@example.test"
	inv := f.createInvitation(t, email)

	if tokens, status, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID); tokens == nil {
		t.Fatalf("first acceptance failed with %d: %s", status, msg)
	}

	tokens, _, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID)
	if tokens != nil {
		t.Fatal("a redeemed invitation was accepted a second time")
	}
	if !strings.Contains(msg, "not valid") {
		t.Errorf("unexpected refusal: %s", msg)
	}
}

// TestConcurrentInvitationRedemption pins that redemption is atomic: two
// simultaneous attempts on one ticket must not both succeed, which would
// otherwise grant membership twice and double-consume the invitation.
func TestConcurrentInvitationRedemption(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	const attempts = 8

	for round := range 6 {
		email := "race" + string(rune('a'+round)) + "@example.test"
		inv := f.createInvitation(t, email)
		ticket := invitationTicket{OrgID: f.orgID, TicketID: inv.GetTicketID(), ClientID: f.clientID}

		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			redeemed  int
			startGate = make(chan struct{})
		)

		for range attempts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-startGate
				if _, err := f.srv.redeemInvitation(ticket, email, time.Now()); err == nil {
					mu.Lock()
					redeemed++
					mu.Unlock()
				}
			}()
		}
		close(startGate)
		wg.Wait()

		if redeemed != 1 {
			t.Fatalf("round %d: %d of %d concurrent redemptions succeeded, want exactly 1",
				round, redeemed, attempts)
		}

		// Exactly one membership, not one per winner.
		user := f.srv.findUser(email)
		if user == nil {
			t.Fatalf("round %d: invitee not created", round)
		}
		count := 0
		for _, m := range f.srv.GetOrgMembers(f.orgID) {
			if m.UserID == user.ID {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("round %d: invitee has %d memberships, want 1", round, count)
		}
	}
}

// TestInvitationMetadataAppliedOnAcceptance covers the design's "possible
// simplification": Auth0 copies invitation metadata onto the profile at
// acceptance, so an invitation can carry org_roles directly and retire both
// the native role carrier and the seeding Action.
func TestInvitationMetadataAppliedOnAcceptance(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	const email = "metadata-accept@example.test"
	inv := f.invitation(email)
	inv.AppMetadata = map[string]any{
		"org_roles": map[string]any{f.orgID: "superadmin"},
		"tier":      "gold",
	}
	inv.UserMetadata = map[string]any{"invited_by": "platform"}
	if err := f.m.Organization.CreateInvitation(context.Background(), f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	tokens, status, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID)
	if tokens == nil {
		t.Fatalf("acceptance failed with %d: %s", status, msg)
	}

	user := f.srv.findUser(email)
	if user == nil {
		t.Fatal("invitee not created")
	}

	// The invitation's org_roles must survive, not be overwritten by seeding
	// from the native role carrier.
	if got := user.AppMetadata.OrgRole(f.orgID); got != "superadmin" {
		t.Errorf("app_metadata.org_roles[%s] = %q, want superadmin from the invitation", f.orgID, got)
	}
	if user.AppMetadata["tier"] != "gold" {
		t.Errorf("invitation app_metadata not applied: %#v", user.AppMetadata)
	}
	if user.UserMetadata["invited_by"] != "platform" {
		t.Errorf("invitation user_metadata not applied: %#v", user.UserMetadata)
	}

	// And the claim follows org_roles.
	roleClaim := strings.TrimSuffix(f.srv.cfg.Issuer, "/") + "/role"
	access := claimsOf(t, f.srv, tokens.AccessToken)
	if access[roleClaim] != "superadmin" {
		t.Errorf("role claim = %v, want superadmin", access[roleClaim])
	}
}

// TestExistingUserAcceptsInvitationToSecondOrg covers an invitee who already
// has an account: they gain membership rather than a duplicate user.
func TestExistingUserAcceptsInvitationToSecondOrg(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	// test_user_2 is seeded in org_test already; invite them to a new org
	// that has its own non-passwordless connection.
	second := "second-org"
	secondOrg := &management.Organization{Name: &second}
	if err := f.m.Organization.Create(ctx, secondOrg); err != nil {
		t.Fatalf("Organization.Create: %v", err)
	}
	if err := f.m.Organization.AddConnection(ctx, secondOrg.GetID(),
		&management.OrganizationConnection{ConnectionID: &f.connectionID}); err != nil {
		t.Fatalf("Organization.AddConnection: %v", err)
	}

	const email = "email@example.test" // test_user_2
	inviter := "Platform Admin"
	invitee := email
	inv := &management.OrganizationInvitation{
		Inviter:  &management.OrganizationInvitationInviter{Name: &inviter},
		Invitee:  &management.OrganizationInvitationInvitee{Email: &invitee},
		ClientID: &f.clientID,
		Roles:    []string{f.adminRoleID},
	}
	if err := f.m.Organization.CreateInvitation(ctx, secondOrg.GetID(), inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	tokens, status, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), email, f.clientID)
	if tokens == nil {
		t.Fatalf("acceptance failed with %d: %s", status, msg)
	}

	// Same user, not a new one.
	user := f.srv.findUser(email)
	if user == nil || user.ID != "test_user_2" {
		t.Fatalf("expected the existing test_user_2, got %+v", user)
	}

	// Member of both organizations now.
	inSecond := false
	for _, m := range f.srv.GetOrgMembers(secondOrg.GetID()) {
		if m.UserID == "test_user_2" && m.Role == "admin" {
			inSecond = true
		}
	}
	if !inSecond {
		t.Error("existing user was not granted admin in the second organization")
	}

	// The original org_test membership is untouched.
	stillFirst := false
	for _, m := range f.srv.GetOrgMembers("org_test") {
		if m.UserID == "test_user_2" {
			stillFirst = true
		}
	}
	if !stillFirst {
		t.Error("accepting an invitation dropped the existing membership")
	}

	// The token is scoped to the organization just joined.
	access := claimsOf(t, f.srv, tokens.AccessToken)
	if access["org_id"] != secondOrg.GetID() {
		t.Errorf("org_id = %v, want the organization just joined (%s)", access["org_id"], secondOrg.GetID())
	}
	if got := user.AppMetadata.OrgRole(secondOrg.GetID()); got != "admin" {
		t.Errorf("org_roles[%s] = %q, want admin", secondOrg.GetID(), got)
	}
}

// TestOrgRolesSeededOnOrdinaryLogin covers requirement 5 for a login that is
// not an invitation: the mock must write app_metadata.org_roles[org] from the
// member role when absent, which is what the production Post-Login Action
// does. Without the write, a Management API reader sees no org_roles at all.
func TestOrgRolesSeededOnOrdinaryLogin(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()

	// test_user_1 is an admin member of org_test with no org_roles entry.
	before := f.srv.getUserByID("test_user_1")
	if before.AppMetadata.OrgRole("org_test") != "" {
		t.Fatal("fixture already has an org_roles entry")
	}

	runLogin(t, f.ts.URL, "+14155551234")

	after := f.srv.getUserByID("test_user_1")
	if got := after.AppMetadata.OrgRole("org_test"); got != "admin" {
		t.Errorf("app_metadata.org_roles[org_test] = %q, want admin seeded from membership", got)
	}
}

// TestOrgRolesSeedingDoesNotOverwrite is the other half of the rule: seeding
// happens only on absence. After the first login org_roles is authoritative
// and a role write owns it, so the native member role must never clobber a
// later change — that is what keeps the two models from fighting.
func TestOrgRolesSeedingDoesNotOverwrite(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	// A role write lands in org_roles, disagreeing with the member role.
	appMeta := map[string]any{
		"tenant_id": "org_test",
		"role":      "admin",
		"org_roles": map[string]any{"org_test": "viewer"},
	}
	if err := f.m.User.Update(ctx, "test_user_1", &management.User{AppMetadata: &appMeta}); err != nil {
		t.Fatalf("User.Update: %v", err)
	}

	runLogin(t, f.ts.URL, "+14155551234")

	after := f.srv.getUserByID("test_user_1")
	if got := after.AppMetadata.OrgRole("org_test"); got != "viewer" {
		t.Errorf("org_roles[org_test] = %q; seeding overwrote an existing entry", got)
	}
}

// TestAcceptanceLeavesOrgRolesToTheAction pins the window PEE's first-admin
// election has to cope with: Auth0 acceptance assigns the native role, and
// org_roles only appears once the Post-Login Action runs at the next login.
// Seeding at acceptance would make the mock kinder than production and hide
// the race.
func TestAcceptanceLeavesOrgRolesToTheAction(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	const email = "window@example.test"
	inv := f.createInvitation(t, email)

	// Redeem without exchanging a token, which is where the Action runs.
	ticket := invitationTicket{
		OrgID:    f.orgID,
		TicketID: inv.GetTicketID(),
		ClientID: f.clientID,
	}
	if _, err := f.srv.redeemInvitation(ticket, email, time.Now()); err != nil {
		t.Fatalf("redeemInvitation: %v", err)
	}

	user := f.srv.findUser(email)
	if user == nil {
		t.Fatal("invitee not created")
	}

	// The native role is assigned...
	var memberRole string
	for _, m := range f.srv.GetOrgMembers(f.orgID) {
		if m.UserID == user.ID {
			memberRole = m.Role
		}
	}
	if memberRole != "admin" {
		t.Errorf("member role = %q, want admin assigned at acceptance", memberRole)
	}

	// ...and the members endpoint reports it, so a consumer that wants to see
	// this member before their first login can.
	members, err := f.m.Organization.Members(ctx, f.orgID)
	if err != nil {
		t.Fatalf("Organization.Members: %v", err)
	}
	var reported string
	for _, m := range members.Members {
		if m.GetUserID() == user.ID && len(m.Roles) == 1 {
			reported = m.Roles[0].GetName()
		}
	}
	if reported != "admin" {
		t.Errorf("members endpoint reports %q, want admin", reported)
	}

	// ...but org_roles is still absent until a login runs the Action.
	if got := user.AppMetadata.OrgRole(f.orgID); got != "" {
		t.Errorf("org_roles[%s] = %q at acceptance; the Action writes it at login", f.orgID, got)
	}

	// One login closes it.
	if seeded := f.srv.seedOrgRoles(user.ID, f.orgID); seeded == nil {
		t.Fatal("seedOrgRoles returned nil")
	} else if got := seeded.AppMetadata.OrgRole(f.orgID); got != "admin" {
		t.Errorf("org_roles[%s] = %q after the Action, want admin", f.orgID, got)
	}
}
