package server

import (
	"bytes"
	"encoding/json"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
)

// selfServiceStrategies are those the SDK documents for allowed_strategies.
var selfServiceStrategies = []string{"oidc", "samlp", "waad", "google-apps", "adfs", "okta", "keycloak-samlp"}

var domainVerificationModes = []string{"none", "optional", "required"}

// defaultTicketTTL is Auth0's ttl_sec default.
const defaultTicketTTL = 5 * 24 * time.Hour

type profileUserAttribute struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IsOptional  bool   `json:"is_optional"`
}

type profileBranding struct {
	LogoURL string `json:"logo_url,omitempty"`
	Colors  *struct {
		Primary string `json:"primary"`
	} `json:"colors,omitempty"`
}

func (b *profileBranding) Clone() *profileBranding {
	if b == nil {
		return nil
	}
	out := *b
	if b.Colors != nil {
		c := *b.Colors
		out.Colors = &c
	}
	return &out
}

type selfServiceProfile struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	Description            string                 `json:"description,omitempty"`
	UserAttributes         []profileUserAttribute `json:"user_attributes"`
	AllowedStrategies      []string               `json:"allowed_strategies,omitempty"`
	CreatedAt              string                 `json:"created_at"`
	UpdatedAt              string                 `json:"updated_at"`
	Branding               *profileBranding       `json:"branding,omitempty"`
	UserAttributeProfileID string                 `json:"user_attribute_profile_id,omitempty"`
}

func (p *selfServiceProfile) Clone() *selfServiceProfile {
	out := *p
	out.AllowedStrategies = slices.Clone(p.AllowedStrategies)
	out.UserAttributes = slices.Clone(p.UserAttributes)
	out.Branding = p.Branding.Clone()
	return &out
}

// selfServiceProfileBody holds every field a profile stores; others are refused.
type selfServiceProfileBody struct {
	Name                   *string                `json:"name"`
	Description            *string                `json:"description"`
	UserAttributes         []profileUserAttribute `json:"user_attributes"`
	AllowedStrategies      *[]string              `json:"allowed_strategies"`
	Branding               *profileBranding       `json:"branding"`
	UserAttributeProfileID *string                `json:"user_attribute_profile_id"`
}

// ssoTicketRequest omits what the mock cannot apply, so the decoder refuses it.
type ssoTicketRequest struct {
	ConnectionID     *string `json:"connection_id"`
	ConnectionConfig *struct {
		Name               string `json:"name"`
		DisplayName        string `json:"display_name"`
		IsDomainConnection *bool  `json:"is_domain_connection"`
		Options            *struct {
			DomainAliases []string `json:"domain_aliases"`
		} `json:"options"`
	} `json:"connection_config"`
	EnabledClients       []string `json:"enabled_clients"`
	EnabledOrganizations []struct {
		OrganizationID          string `json:"organization_id"`
		AssignMembershipOnLogin *bool  `json:"assign_membership_on_login"`
		ShowAsButton            *bool  `json:"show_as_button"`
	} `json:"enabled_organizations"`
	TTLSec              int `json:"ttl_sec"`
	DomainAliasesConfig *struct {
		DomainVerification string `json:"domain_verification"`
	} `json:"domain_aliases_config"`
}

type ssoTicket struct {
	ID        string
	ProfileID string
	Request   ssoTicketRequest
	ExpiresAt time.Time
}

// handleSelfServiceProfiles serves GET and POST /api/v2/self-service-profiles.
func (s *Server) handleSelfServiceProfiles(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.listSelfServiceProfiles(w, r)
	case http.MethodPost:
		s.createSelfServiceProfile(w, r)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSelfServiceProfile serves a profile and its sso-ticket subresource;
// any other path 404s.
func (s *Server) handleSelfServiceProfile(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		return
	}

	segments := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/self-service-profiles/"), "/"), "/")
	id := segments[0]
	switch {
	case id == "":
	case len(segments) == 1:
		switch r.Method {
		case http.MethodGet:
			s.getSelfServiceProfile(w, id)
		case http.MethodPatch:
			s.updateSelfServiceProfile(w, r, id)
		case http.MethodDelete:
			s.deleteSelfServiceProfile(w, id)
		default:
			writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	case len(segments) == 2 && segments[1] == "sso-ticket" && r.Method == http.MethodPost:
		s.createSSOTicket(w, r, id)
		return
	case len(segments) == 4 && segments[1] == "sso-ticket" && segments[3] == "revoke" && r.Method == http.MethodPost:
		s.revokeSSOTicket(w, id, segments[2])
		return
	}
	writeAuth0Error(w, http.StatusNotFound, "route not implemented by the auth0 mock: "+r.URL.Path)
}

func profileNotFound(id string) string { return "Profile with ID: " + id + " not found" }

func (s *Server) listSelfServiceProfiles(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	all := make([]*selfServiceProfile, 0, len(s.selfServiceProfiles))
	for _, p := range s.selfServiceProfiles {
		all = append(all, p.Clone())
	}
	s.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt < all[j].CreatedAt || (all[i].CreatedAt == all[j].CreatedAt && all[i].ID < all[j].ID)
	})

	lo, hi, window := paginate(r, len(all))
	page := all[lo:hi]
	if r.URL.Query().Get("include_totals") != "true" {
		_ = json.NewEncoder(w).Encode(page)
		return
	}
	// No length, as recorded (TestSelfServiceProfileManager_List.yaml).
	_ = json.NewEncoder(w).Encode(map[string]any{
		"self_service_profiles": page, "start": window.Start, "limit": window.Limit, "total": window.Total,
	})
}

// decodeProfileBody decodes a profile write, refusing what Auth0 refuses.
func decodeProfileBody(w http.ResponseWriter, r *http.Request) (*selfServiceProfileBody, bool) {
	var body selfServiceProfileBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return nil, false
	}
	if body.AllowedStrategies != nil {
		for _, st := range *body.AllowedStrategies {
			if !slices.Contains(selfServiceStrategies, st) {
				writeAuth0Error(w, http.StatusBadRequest, "allowed_strategies: unsupported strategy "+st)
				return nil, false
			}
		}
	}
	for _, a := range body.UserAttributes {
		if a.Name == "" {
			writeAuth0Error(w, http.StatusBadRequest, "user_attributes: name is required")
			return nil, false
		}
	}
	// By presence, as the SDK refuses it; validate also checks the result.
	if len(body.UserAttributes) > 0 && body.UserAttributeProfileID != nil {
		writeAuth0Error(w, http.StatusBadRequest, "only one of user_attributes or user_attribute_profile_id can be set")
		return nil, false
	}
	if b := body.Branding; b != nil && b.LogoURL != "" && !strings.HasPrefix(b.LogoURL, "https://") {
		writeAuth0Error(w, http.StatusBadRequest, "branding.logo_url must be an https URL")
		return nil, false
	}
	return &body, true
}

func (p *selfServiceProfile) apply(b *selfServiceProfileBody) {
	if b.Name != nil {
		p.Name = *b.Name
	}
	if b.Description != nil {
		p.Description = *b.Description
	}
	if b.UserAttributes != nil {
		p.UserAttributes = b.UserAttributes
	}
	if b.AllowedStrategies != nil {
		p.AllowedStrategies = slices.Clone(*b.AllowedStrategies)
	}
	if b.Branding != nil {
		p.Branding = b.Branding
	}
	if b.UserAttributeProfileID != nil {
		p.UserAttributeProfileID = *b.UserAttributeProfileID
	}
}

// validate refuses a profile Auth0 would not store.
func (p *selfServiceProfile) validate() string {
	if p.Name == "" {
		return "name is required"
	}
	if len(p.UserAttributes) > 0 && p.UserAttributeProfileID != "" {
		return "only one of user_attributes or user_attribute_profile_id can be set"
	}
	return ""
}

func auth0Timestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func (s *Server) createSelfServiceProfile(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeProfileBody(w, r)
	if !ok {
		return
	}
	now := auth0Timestamp(time.Now())
	p := &selfServiceProfile{ID: "ssp_" + s.generateID(), UserAttributes: []profileUserAttribute{}, CreatedAt: now, UpdatedAt: now}
	p.apply(body)
	if err := p.validate(); err != "" {
		writeAuth0Error(w, http.StatusBadRequest, err)
		return
	}

	s.mu.Lock()
	s.selfServiceProfiles[p.ID] = p
	out := p.Clone()
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) getSelfServiceProfile(w http.ResponseWriter, id string) {
	s.mu.RLock()
	p, ok := s.selfServiceProfiles[id]
	var out *selfServiceProfile
	if ok {
		out = p.Clone()
	}
	s.mu.RUnlock()
	if !ok {
		writeAuth0Error(w, http.StatusNotFound, profileNotFound(id))
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) updateSelfServiceProfile(w http.ResponseWriter, r *http.Request, id string) {
	body, ok := decodeProfileBody(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	p, ok := s.selfServiceProfiles[id]
	if !ok {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusNotFound, profileNotFound(id))
		return
	}
	next := p.Clone()
	next.apply(body)
	if err := next.validate(); err != "" {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusBadRequest, err)
		return
	}
	next.UpdatedAt = auth0Timestamp(time.Now())
	s.selfServiceProfiles[id] = next
	out := next.Clone()
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(out)
}

// deleteSelfServiceProfile answers 204 even when absent, as recorded
// (TestSelfServiceProfileManager_Delete.yaml).
func (s *Server) deleteSelfServiceProfile(w http.ResponseWriter, id string) {
	s.mu.Lock()
	delete(s.selfServiceProfiles, id)
	for tid, t := range s.ssoTickets {
		if t.ProfileID == id {
			delete(s.ssoTickets, tid)
		}
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// createSSOTicket refuses a ticket that could never complete.
func (s *Server) createSSOTicket(w http.ResponseWriter, r *http.Request, profileID string) {
	var req ssoTicketRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body (fields the auth0 mock does not implement are refused): "+err.Error())
		return
	}
	if (req.ConnectionID == nil) == (req.ConnectionConfig == nil) {
		writeAuth0Error(w, http.StatusBadRequest, "exactly one of connection_id or connection_config is required")
		return
	}
	if req.ConnectionConfig != nil && req.ConnectionConfig.Name == "" {
		writeAuth0Error(w, http.StatusBadRequest, "connection_config.name is required")
		return
	}
	if req.DomainAliasesConfig != nil && !slices.Contains(domainVerificationModes, req.DomainAliasesConfig.DomainVerification) {
		writeAuth0Error(w, http.StatusBadRequest, "domain_aliases_config.domain_verification must be none, optional or required")
		return
	}
	// Bounded so the conversion to a duration cannot overflow.
	if req.TTLSec < 0 || req.TTLSec > math.MaxInt64/int(time.Second) {
		writeAuth0Error(w, http.StatusBadRequest, "ttl_sec is out of range")
		return
	}

	status, msg, ticketURL := s.storeSSOTicket(profileID, req)
	if ticketURL == "" {
		writeAuth0Error(w, status, msg)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"ticket": ticketURL})
}

// storeSSOTicket answers a refusal or the ticket's link, so the caller writes
// the response after the lock is released.
func (s *Server) storeSSOTicket(profileID string, req ssoTicketRequest) (int, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	profile, ok := s.selfServiceProfiles[profileID]
	if !ok {
		return http.StatusNotFound, profileNotFound(profileID), ""
	}
	if req.ConnectionID != nil {
		conn, ok := s.connections[*req.ConnectionID]
		if !ok {
			return http.StatusNotFound, "connection not found", ""
		}
		if !slices.Contains(profile.AllowedStrategies, conn.Strategy) {
			return http.StatusBadRequest, "connection strategy " + conn.Strategy + " is not allowed by the profile", ""
		}
	}
	if err := s.ticketTargetsLocked(req); err != "" {
		return http.StatusBadRequest, err, ""
	}

	ttl := defaultTicketTTL
	if req.TTLSec > 0 {
		ttl = time.Duration(req.TTLSec) * time.Second
	}
	now := time.Now()
	for tid, old := range s.ssoTickets {
		if now.After(old.ExpiresAt) {
			delete(s.ssoTickets, tid)
		}
	}
	t := &ssoTicket{ID: s.generateID(), ProfileID: profileID, Request: req, ExpiresAt: now.Add(ttl)}
	s.ssoTickets[t.ID] = t

	return http.StatusCreated, "", s.ticketURL(t.ID)
}

// ticketTargetsLocked refuses clients or organizations that do not exist.
// Caller holds the lock.
func (s *Server) ticketTargetsLocked(req ssoTicketRequest) string {
	for _, c := range req.EnabledClients {
		if _, ok := s.clients[c]; !ok {
			return "unknown client " + c
		}
	}
	for _, o := range req.EnabledOrganizations {
		if _, ok := s.organizations[o.OrganizationID]; !ok {
			return "unknown organization " + o.OrganizationID
		}
	}
	return ""
}

func (s *Server) ticketURL(id string) string {
	return strings.TrimRight(s.cfg.Issuer, "/") + "/self-service/connections-flow?ticket=" + url.QueryEscape(id)
}

// revokeSSOTicket answers 202, as Auth0 documents.
func (s *Server) revokeSSOTicket(w http.ResponseWriter, profileID, ticketID string) {
	s.mu.Lock()
	if t, ok := s.ssoTickets[ticketID]; ok && t.ProfileID == profileID {
		delete(s.ssoTickets, ticketID)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

var connectionsFlowPage = template.Must(template.New("flow").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>SSO setup</title>
<style>body{font-family:sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}label{display:block;margin:.75rem 0}input,select{width:100%;padding:.4rem}</style>
</head><body>
<h1>SSO setup</h1>
{{if .Error}}<p>{{.Error}}</p>{{else if .Done}}<p>Connection {{.Name}} is set up. You can close this tab.</p>{{else}}
<p>{{if .Editing}}Editing connection {{.Name}}.{{else}}Creating connection {{.Name}}.{{end}} The auth0 mock treats every domain as verified.</p>
<form method="post">
<label>Identity provider
{{if .Editing}}<input name="strategy" value="{{.Strategy}}" readonly>{{else}}<select name="strategy">{{range .Strategies}}<option>{{.}}</option>{{end}}</select>{{end}}
</label>
<label>Display name <input name="display_name" value="{{.DisplayName}}"></label>
<label>Email domains, comma separated <input name="domain_aliases" value="{{.Domains}}"></label>
<button type="submit">Finish setup</button>
</form>{{end}}
</body></html>`))

type connectionsFlowView struct {
	Error       string
	Done        bool
	Editing     bool
	Name        string
	Strategy    string
	Strategies  []string
	DisplayName string
	Domains     string
}

// handleConnectionsFlow is the page a ticket opens: GET shows the form, POST
// creates or edits the connection, enables it and spends the ticket.
func (s *Server) handleConnectionsFlow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("ticket")

	var view connectionsFlowView
	status := http.StatusOK
	// Read before taking the lock, so a slow client cannot hold it.
	var formErr error
	if r.Method == http.MethodPost {
		formErr = r.ParseForm()
	}
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		t, ok := s.ssoTickets[id]
		if !ok || time.Now().After(t.ExpiresAt) {
			status, view.Error = http.StatusBadRequest, "This setup link is invalid, expired or already used."
			return
		}
		profile, ok := s.selfServiceProfiles[t.ProfileID]
		if !ok {
			status, view.Error = http.StatusBadRequest, "This setup link's profile no longer exists."
			return
		}
		view.Strategies = profile.AllowedStrategies

		var conn *config.Connection
		if t.Request.ConnectionID != nil {
			if conn, ok = s.connections[*t.Request.ConnectionID]; !ok {
				status, view.Error = http.StatusBadRequest, "The connection this link edits no longer exists."
				return
			}
			view.Editing, view.Name, view.Strategy, view.DisplayName = true, conn.Name, conn.Strategy, conn.DisplayName
			view.Domains = strings.Join(connectionDomainAliases(conn), ", ")
		} else {
			cc := t.Request.ConnectionConfig
			view.Name, view.DisplayName = cc.Name, cc.DisplayName
			if cc.Options != nil {
				view.Domains = strings.Join(cc.Options.DomainAliases, ", ")
			}
		}
		if r.Method == http.MethodGet {
			return
		}

		if formErr != nil {
			status, view.Error = http.StatusBadRequest, "Could not read the form."
			return
		}
		// Rechecked: what the ticket names may have gone since it was issued.
		if err := s.ticketTargetsLocked(t.Request); err != "" {
			status, view.Error = http.StatusBadRequest, err
			return
		}
		pairings := make([]config.OrganizationConnection, 0, len(t.Request.EnabledOrganizations))
		for _, o := range t.Request.EnabledOrganizations {
			connID := ""
			if conn != nil {
				connID = conn.ID
			}
			oc := s.ticketPairingLocked(o.OrganizationID, connID, o.AssignMembershipOnLogin, o.ShowAsButton)
			if err := validOrgConnection(oc); err != nil {
				status, view.Error = http.StatusBadRequest, err.Error()
				return
			}
			pairings = append(pairings, oc)
		}
		domains := splitDomains(r.PostFormValue("domain_aliases"))
		if conn == nil {
			strategy := r.PostFormValue("strategy")
			if !slices.Contains(profile.AllowedStrategies, strategy) {
				status, view.Error = http.StatusBadRequest, "That identity provider is not allowed."
				return
			}
			if s.connectionByNameLocked(view.Name) != nil {
				status, view.Error = http.StatusConflict, "A connection named "+view.Name+" already exists."
				return
			}
			conn = &config.Connection{ID: "con_" + s.generateID(), Name: view.Name, DisplayName: view.DisplayName, Strategy: strategy, Options: map[string]any{}}
			if cc := t.Request.ConnectionConfig; cc.IsDomainConnection != nil {
				conn.IsDomainConn = *cc.IsDomainConnection
			}
			s.connections[conn.ID] = conn
		}
		if dn := strings.TrimSpace(r.PostFormValue("display_name")); dn != "" {
			conn.DisplayName = dn
		}
		if conn.Options == nil {
			conn.Options = map[string]any{}
		}
		if len(domains) > 0 {
			// []any, as JSON decodes it, so clones copy it.
			aliases := make([]any, len(domains))
			for i, d := range domains {
				aliases[i] = d
			}
			conn.Options["domain_aliases"] = aliases
		} else {
			delete(conn.Options, "domain_aliases")
		}
		for _, c := range t.Request.EnabledClients {
			if !slices.Contains(conn.EnabledClients, c) {
				conn.EnabledClients = append(conn.EnabledClients, c)
			}
		}
		for _, oc := range pairings {
			oc.ConnectionID = conn.ID
			s.putOrgConnectionLocked(oc)
		}
		delete(s.ssoTickets, t.ID)
		if t.Request.DomainAliasesConfig != nil && t.Request.DomainAliasesConfig.DomainVerification != "none" && len(domains) > 0 {
			log.Printf("self-service: treating domains %v of %s as verified", domains, conn.Name)
		}
		view.Done, view.Name = true, conn.Name
	}()

	var buf bytes.Buffer
	if err := connectionsFlowPage.Execute(&buf, view); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// ticketPairingLocked returns the existing pairing updated, or a new one when
// connID is empty or unpaired. Caller holds the lock.
func (s *Server) ticketPairingLocked(orgID, connID string, assign, show *bool) config.OrganizationConnection {
	oc := config.OrganizationConnection{OrgID: orgID, ConnectionID: connID, ShowAsButton: true}
	if connID != "" {
		for _, existing := range s.orgConnections[orgID] {
			if existing.ConnectionID == connID {
				oc = existing
			}
		}
	}
	if assign != nil {
		oc.AssignMembershipOnLogin = *assign
	}
	if show != nil {
		oc.ShowAsButton = *show
	}
	return oc
}

// putOrgConnectionLocked stores or replaces a pairing. Caller holds the lock.
func (s *Server) putOrgConnectionLocked(oc config.OrganizationConnection) {
	pairings := s.orgConnections[oc.OrgID]
	if i := slices.IndexFunc(pairings, func(p config.OrganizationConnection) bool { return p.ConnectionID == oc.ConnectionID }); i >= 0 {
		pairings[i] = oc
	} else {
		pairings = append(pairings, oc)
	}
	s.orgConnections[oc.OrgID] = pairings
}

// connectionDomainAliases reads []string from Go config and []any from JSON.
func connectionDomainAliases(c *config.Connection) []string {
	switch v := c.Options["domain_aliases"].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, d := range v {
			if str, ok := d.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func splitDomains(raw string) []string {
	var out []string
	for _, d := range strings.Split(raw, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}
