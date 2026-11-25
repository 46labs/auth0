package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/46labs/auth0/pkg/config"
)

// Organization settings on a client, as Auth0 names them.
const (
	orgUsageRequire        = "require"
	orgBehaviorPostLogin   = "post_login_prompt"
	errNoOrganizations     = "client requires organization membership, but user does not belong to any organization"
	errOrganizationMissing = "parameter organization is required for this client"
)

// validateOIDCForPrompt refuses post_login_prompt on a client explicitly
// not OIDC conformant: Auth0 requires conformance for it. Unset is left
// alone for configs that predate the field.
func validateOIDCForPrompt(behavior string, oidc *bool) error {
	if behavior == orgBehaviorPostLogin && oidc != nil && !*oidc {
		return fmt.Errorf("organization_require_behavior post_login_prompt needs oidc_conformant true")
	}
	return nil
}

// validateOrgSettings checks a client's organization settings. Empty
// means unset: organization logins stay permitted, unlike Auth0's deny
// default, for configs and clients that predate the settings. An explicit
// empty value on the wire is refused (validateOrgWrite). pre_login_prompt
// is not modelled, so it is refused rather than stored and ignored.
func validateOrgSettings(usage, behavior string) error {
	switch usage {
	case "", "deny", "allow", orgUsageRequire:
	default:
		return fmt.Errorf("organization_usage must be deny, allow, or require")
	}
	switch behavior {
	case "", "no_prompt", orgBehaviorPostLogin:
	default:
		return fmt.Errorf("organization_require_behavior must be no_prompt or post_login_prompt (the mock does not model pre_login_prompt)")
	}
	return nil
}

// loginTx is a sign-in past its code: it may still wait on the
// organization picker or the second factor before its code is minted.
type loginTx struct {
	User       *config.User
	Resolved   string
	Params     url.Values
	Query      string
	LogParams  url.Values
	Identifier string
	OrgID      string
	Connection string
	// Invited logins name their organization through the ticket.
	Invited bool
	// SessionID is the login session (sid, event.session.id).
	SessionID string
	// Claims as the post-login Actions left them, once they ran.
	IDClaims     jwt.MapClaims
	AccessClaims jwt.MapClaims
	Audience     string
	// TokenOrg is the organization the claims were built for.
	TokenOrg string
	// NoTenantOrg: the client denies organizations.
	NoTenantOrg bool
}

// completeLogin takes a sign-in from its verified code to its authorization
// code, as Auth0's login transaction does: the organization (asked for
// after sign-in when the client requires one and prompts), then the
// post-login Actions, then the second factor an Action asked for. page is
// the login page's session, which the picker and the second factor post
// back to.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, page string, tx *loginTx) {
	clientID := tx.Params.Get("client_id")

	if tx.OrgID == "" && !tx.Invited {
		if client := s.lookupClient(clientID); client != nil && client.OrganizationUsage == orgUsageRequire {
			if client.OrganizationRequireBehavior != orgBehaviorPostLogin {
				s.dropLogin(page)
				s.loginError(w, r, tx, "invalid_request", errOrganizationMissing)
				return
			}
			orgs := s.userOrganizations(tx.User.ID, tx.Resolved)
			switch len(orgs) {
			case 0:
				s.dropLogin(page)
				s.loginError(w, r, tx, "invalid_request", errNoOrganizations)
				return
			case 1:
				tx.OrgID = orgs[0].ID
			default:
				s.holdLogin(page, tx)
				s.renderStep(w, http.StatusOK, organizationPage, map[string]any{
					"SessionID": page, "Branding": s.cfg.Branding, "Organizations": orgs,
				})
				return
			}
			if err := s.authorizeOrgLogin(tx.User, tx.OrgID, tx.Params.Get("connection")); err != nil {
				s.dropLogin(page)
				s.loginError(w, r, tx, "access_denied", err.Error())
				return
			}
		}
	}

	if tx.AccessClaims == nil {
		// The verified identity first, so the claims and the Actions see it
		// (email_verified after a passwordless code).
		s.mu.Lock()
		s.recordLoginLocked(tx.User.ID, tx.Identifier, tx.Resolved)
		if stored := s.users[tx.User.ID]; stored != nil {
			tx.User = stored.Clone()
		}
		s.mu.Unlock()
		// The organization the tokens are for, fixed before the Actions run
		// (one may change the user's stored tenant).
		// A client that denies organizations gets none, not even the
		// user's stored tenant.
		denies := false
		if c := s.lookupClient(clientID); c != nil && c.OrganizationUsage == "deny" {
			denies = true
		}
		tx.NoTenantOrg = denies
		tx.TokenOrg = tx.OrgID
		if tx.TokenOrg == "" && !denies {
			tx.TokenOrg = tx.User.AppMetadata.TenantID()
		}
		user, idClaims, accessClaims, audience := s.loginTokenClaims(*tx.User, clientID, tx.TokenOrg, tx.Query,
			tx.Params.Get("scope"), tx.Params.Get("nonce"), tx.SessionID, time.Now())
		// The Actions see the request that started the login (GET
		// /authorize), not whichever login page step posted last.
		req := requestFromToken(r, tx.Query, "oidc-basic-profile", nil)
		req.Method, req.Body = http.MethodGet, map[string]string{}
		req.SessionID = tx.SessionID
		req.Connection = tx.Resolved
		req.TenantOrg = tx.OrgID == ""
		req.NoTenantOrg = denies
		mfa, denied := s.runPostLogin(&user, clientID, tx.TokenOrg, "oidc-basic-profile", req, idClaims, accessClaims)
		if denied != nil {
			// The login's own record, failed: one record per attempt.
			s.emitPendingLogin(s.loginRecord(r, tx), false)
			// Ended: the same code cannot be posted again to rerun the Actions.
			s.dropLogin(page)
			s.redirectLoginError(w, tx, "access_denied", denied.reason)
			return
		}
		// A copy taken under the lock: an Action's metadata writes share maps
		// with the stored user, which the Management API may change while
		// this login waits.
		s.mu.RLock()
		tx.User = user.Clone()
		s.mu.RUnlock()
		tx.IDClaims, tx.AccessClaims, tx.Audience = idClaims, accessClaims, audience
		if mfa && !s.sessionPassedMFA(tx.SessionID) {
			s.holdLogin(page, tx)
			s.renderStep(w, http.StatusOK, mfaPage, map[string]any{"SessionID": page, "Branding": s.cfg.Branding})
			return
		}
	}

	s.mintLoginCode(w, r, page, tx)
}

// continueLogin answers the organization picker and the second factor.
func (s *Server) continueLogin(w http.ResponseWriter, r *http.Request, page string) {
	// Claim the waiting login: a second submission for the same page finds
	// nothing until this one puts it back or finishes it.
	s.mu.Lock()
	tx, ok := s.logins[page]
	delete(s.logins, page)
	s.mu.Unlock()
	if !ok {
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	if orgID := r.FormValue("organization"); orgID != "" && tx.OrgID == "" && tx.AccessClaims == nil {
		member := false
		for _, o := range s.userOrganizations(tx.User.ID, tx.Resolved) {
			member = member || o.ID == orgID
		}
		if !member {
			s.holdLogin(page, tx)
			http.Error(w, "Not a member of that organization", http.StatusBadRequest)
			return
		}
		tx.OrgID = orgID
		if err := s.authorizeOrgLogin(tx.User, orgID, tx.Params.Get("connection")); err != nil {
			s.dropLogin(page)
			s.loginError(w, r, tx, "access_denied", err.Error())
			return
		}
		s.completeLogin(w, r, page, tx)
		return
	}

	if code := r.FormValue("mfa_code"); code != "" && tx.AccessClaims != nil {
		if code != passwordlessCode {
			s.holdLogin(page, tx)
			s.renderStep(w, http.StatusBadRequest, mfaPage, map[string]any{
				"SessionID": page, "Branding": s.cfg.Branding, "Error": "That code is not right. Try again.",
			})
			return
		}
		s.mu.Lock()
		s.mfaSessions[tx.SessionID] = time.Now()
		s.mu.Unlock()
		s.mintLoginCode(w, r, page, tx)
		return
	}

	s.holdLogin(page, tx)
	http.Error(w, "Invalid request", http.StatusBadRequest)
}

// loginTokenClaims builds a login's token claims: the latest user record
// with its organization roles seeded, the ID token's claims (auth_time,
// nonce, sid), and the access token's for the audience the login asked for.
func (s *Server) loginTokenClaims(user config.User, clientID, orgID, query, scope, nonce, sessionID string, now time.Time) (config.User, jwt.MapClaims, jwt.MapClaims, string) {
	// orgID is resolved by the caller (named, or the stored tenant where the
	// client allows it).
	// Post-Login Action parity, and it reads back the latest AppMetadata.
	if seeded := s.seedOrgRoles(user.ID, orgID); seeded != nil {
		user = *seeded
	} else if latest := s.getUserByID(user.ID); latest != nil {
		user = *latest
	}
	idClaims := s.idTokenClaims(&user, clientID, orgID, now)
	idClaims["auth_time"] = now.Unix()
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	if sessionID != "" {
		idClaims["sid"] = sessionID
	}
	audience := s.authorizeAudience(query)
	accessClaims := s.accessTokenClaims(&user, clientID, audience, scope, orgID, now)
	return user, idClaims, accessClaims, audience
}

// mintLoginCode issues the authorization code for a finished sign-in and
// sends the browser back to the application.
func (s *Server) mintLoginCode(w http.ResponseWriter, r *http.Request, page string, tx *loginTx) {
	redirectURL := parseRedirectURI(tx.Params.Get("redirect_uri"))
	if redirectURL == nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	code := s.generateID()
	state := &authCode{
		User:          *tx.User,
		CodeChallenge: tx.Params.Get("code_challenge"),
		Nonce:         tx.Params.Get("nonce"),
		Scope:         tx.Params.Get("scope"),
		ClientID:      tx.Params.Get("client_id"),
		OrgID:         tx.OrgID,
		ConnectionID:  tx.Params.Get("connection"),
		Connection:    tx.Resolved,
		Query:         tx.Query,
		SessionID:     tx.SessionID,
		IDClaims:      tx.IDClaims,
		AccessClaims:  tx.AccessClaims,
		Audience:      tx.Audience,
		TokenOrg:      tx.TokenOrg,
		NoTenantOrg:   tx.NoTenantOrg,
		IssuedAt:      time.Now(),
	}

	s.mu.Lock()
	s.authCodes[code] = state
	delete(s.pending, page)
	delete(s.logins, page)
	// The second factor counted for this login only; nothing reads it after.
	delete(s.mfaSessions, tx.SessionID)
	s.mu.Unlock()
	// The login finished here: Actions ran and any second factor passed.
	s.emitPendingLogin(s.loginRecord(r, tx), true)

	query := redirectURL.Query()
	query.Set("code", code)
	if st := tx.Params.Get("state"); st != "" {
		query.Set("state", st)
	}
	redirectURL.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// loginError logs a failed sign-in and ends it the way Auth0 does.
func (s *Server) loginError(w http.ResponseWriter, r *http.Request, tx *loginTx, code, description string) {
	s.emitLoginLog(r, tx.LogParams, "f", description, tx.User, tx.Identifier, tx.OrgID)
	s.redirectLoginError(w, tx, code, description)
}

// redirectLoginError sends the browser back to the application with error
// and error_description.
func (s *Server) redirectLoginError(w http.ResponseWriter, tx *loginTx, code, description string) {
	u := parseRedirectURI(tx.Params.Get("redirect_uri"))
	if u == nil {
		http.Error(w, description, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if st := tx.Params.Get("state"); st != "" {
		q.Set("state", st)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

// loginRecord is the login's sign-in log record, with the organization it
// ended in.
func (s *Server) loginRecord(r *http.Request, tx *loginTx) map[string]any {
	return s.loginLog(r, withConnection(tx.LogParams, tx.Resolved), "s", "Successful login", tx.User, tx.Identifier, tx.OrgID)
}

// holdLogin parks a login on its organization or second-factor step. The
// first step's transaction ends here: its code cannot be posted again to
// start over and skip the step.
func (s *Server) holdLogin(page string, tx *loginTx) {
	s.mu.Lock()
	s.logins[page] = tx
	delete(s.pending, page)
	s.mu.Unlock()
}

func (s *Server) dropLogin(page string) {
	s.mu.Lock()
	delete(s.logins, page)
	delete(s.pending, page)
	s.mu.Unlock()
}

// loginOrganization is one choice on the organization picker.
type loginOrganization struct {
	ID          string
	Name        string
	DisplayName string
}

// userOrganizations lists the organizations the user is a member of and
// may sign in to through connection (the one the login used), by display
// name.
func (s *Server) userOrganizations(userID, connection string) []loginOrganization {
	s.mu.RLock()
	defer s.mu.RUnlock()
	connectionID := s.connectionIDByName(connection)
	var out []loginOrganization
	for orgID, members := range s.members {
		for _, m := range members {
			if m.UserID != userID {
				continue
			}
			// A connection the mock does not model filters nothing, as
			// connectionAllowedLocked treats it.
			if org := s.organizations[orgID]; org != nil && (connectionID == "" || s.isConnectionEnabled(orgID, connectionID)) {
				display := org.DisplayName
				if display == "" {
					display = org.Name
				}
				out = append(out, loginOrganization{ID: org.ID, Name: org.Name, DisplayName: display})
			}
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DisplayName < out[j].DisplayName })
	return out
}

func (s *Server) renderStep(w http.ResponseWriter, status int, page *template.Template, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = page.Execute(w, data)
}

// stepStyle is shared by the picker and the second factor.
const stepStyle = `<style>
body{font-family:system-ui,sans-serif;background:#f5f5f4;color:#1c1917;margin:0;display:grid;place-items:center;min-height:100vh}
main{background:#fff;border:1px solid #d6d3d1;border-radius:8px;padding:2rem;width:min(22rem,90vw)}
h1{font-size:1.25rem;margin:0 0 1rem}
label{display:block;font-weight:600;margin-bottom:.25rem}
input{width:100%;box-sizing:border-box;padding:.6rem;border:1px solid #78716c;border-radius:6px;font-size:1rem}
button{width:100%;margin-top:.75rem;padding:.6rem;border:0;border-radius:6px;font-size:1rem;color:#fff;cursor:pointer}
ul{list-style:none;padding:0;margin:0}
p.error{color:#b91c1c}
</style>`

var organizationPage = template.Must(template.New("organization").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Choose an organization · {{.Branding.ServiceName}}</title>` + stepStyle + `</head>
<body><main>
<h1>Choose an organization</h1>
<form method="post" action="/authorize">
<input type="hidden" name="session_id" value="{{.SessionID}}">
<ul>{{range .Organizations}}<li><button type="submit" name="organization" value="{{.ID}}" style="background:{{or $.Branding.PrimaryColor "#1f2937"}}">{{.DisplayName}}</button></li>{{end}}</ul>
</form>
</main></body></html>`))

var mfaPage = template.Must(template.New("mfa").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify it's you · {{.Branding.ServiceName}}</title>` + stepStyle + `</head>
<body><main>
<h1>Verify it's you</h1>
<form method="post" action="/authorize">
<input type="hidden" name="session_id" value="{{.SessionID}}">
<label for="mfa_code">Code from your authenticator app</label>
<input id="mfa_code" name="mfa_code" inputmode="numeric" autocomplete="one-time-code" required>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<button type="submit" style="background:{{or .Branding.PrimaryColor "#1f2937"}}">Continue</button>
</form>
</main></body></html>`))

// validateOrgWrite refuses an explicitly empty organization setting in a
// Management API write: Auth0 takes only its enum values.
func validateOrgWrite(usage, behavior *string) error {
	if (usage != nil && *usage == "") || (behavior != nil && *behavior == "") {
		return fmt.Errorf("organization settings cannot be empty")
	}
	return nil
}
