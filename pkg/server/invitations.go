package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
)

// ISO 8601 rendering the Management API uses for created_at / expires_at.
const auth0TimeFormat = "2006-01-02T15:04:05.000Z"

// invitationView is the wire shape. Auth0 nests inviter and invitee as
// objects and reports expires_at, not the ttl_sec that was sent in.
type invitationView struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	Inviter        invitationParty `json:"inviter"`
	Invitee        invitationEmail `json:"invitee"`
	InvitationURL  string          `json:"invitation_url"`
	TicketID       string          `json:"ticket_id"`
	ClientID       string          `json:"client_id"`
	ConnectionID   string          `json:"connection_id,omitempty"`
	AppMetadata    map[string]any  `json:"app_metadata,omitempty"`
	UserMetadata   map[string]any  `json:"user_metadata,omitempty"`
	Roles          []string        `json:"roles,omitempty"`
	CreatedAt      string          `json:"created_at"`
	ExpiresAt      string          `json:"expires_at"`
}

type invitationParty struct {
	Name string `json:"name"`
}

type invitationEmail struct {
	Email string `json:"email"`
}

func viewInvitation(inv *config.OrganizationInvitation) invitationView {
	return invitationView{
		ID:             inv.ID,
		OrganizationID: inv.OrganizationID,
		Inviter:        invitationParty{Name: inv.InviterName},
		Invitee:        invitationEmail{Email: inv.InviteeEmail},
		InvitationURL:  inv.InvitationURL,
		TicketID:       inv.TicketID,
		ClientID:       inv.ClientID,
		ConnectionID:   inv.ConnectionID,
		AppMetadata:    inv.AppMetadata,
		UserMetadata:   inv.UserMetadata,
		Roles:          inv.Roles,
		CreatedAt:      inv.CreatedAt.UTC().Format(auth0TimeFormat),
		ExpiresAt:      inv.ExpiresAt.UTC().Format(auth0TimeFormat),
	}
}

// handleOrganizationInvitations serves the invitations collection:
// GET /api/v2/organizations/{id}/invitations and POST to create one.
func (s *Server) handleOrganizationInvitations(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	orgID := orgIDFromPath(r.URL.Path)

	switch r.Method {
	case http.MethodGet:
		s.listOrganizationInvitations(w, r, orgID)
	case http.MethodPost:
		s.createOrganizationInvitation(w, r, orgID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleOrganizationInvitation serves a single invitation: GET to read and
// DELETE to revoke .../invitations/{invitationID}.
func (s *Server) handleOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	orgID := orgIDFromPath(r.URL.Path)
	segments := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/organizations/"), "/"), "/")
	invitationID := segments[len(segments)-1]

	switch r.Method {
	case http.MethodGet:
		s.getOrganizationInvitation(w, orgID, invitationID)
	case http.MethodDelete:
		s.deleteOrganizationInvitation(w, orgID, invitationID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// pendingInvitations returns the unexpired invitations and prunes the rest:
// an invitation lapses on its TTL rather than being reported as pending.
// Caller holds the write lock.
func (s *Server) pendingInvitations(orgID string, now time.Time) []config.OrganizationInvitation {
	stored := s.invitations[orgID]

	expired := false
	for i := range stored {
		if stored[i].IsExpired(now) {
			expired = true
			break
		}
	}
	if !expired {
		return stored
	}

	kept := make([]config.OrganizationInvitation, 0, len(stored))
	for _, inv := range stored {
		if inv.IsExpired(now) {
			continue
		}
		kept = append(kept, inv)
	}
	s.invitations[orgID] = kept
	return kept
}

func (s *Server) listOrganizationInvitations(w http.ResponseWriter, r *http.Request, orgID string) {
	// Write lock: listing prunes expired invitations.
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.organizations[orgID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}

	pending := s.pendingInvitations(orgID, time.Now())

	lo, hi, window := paginate(r, len(pending))
	page := pending[lo:hi]

	views := make([]invitationView, 0, len(page))
	for i := range page {
		views = append(views, viewInvitation(&page[i]))
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"invitations": views,
		"start":       window.Start,
		"limit":       window.Limit,
		"length":      len(views),
		"total":       window.Total,
	})
}

func (s *Server) createOrganizationInvitation(w http.ResponseWriter, r *http.Request, orgID string) {
	var req struct {
		Inviter *struct {
			Name string `json:"name"`
		} `json:"inviter"`
		Invitee *struct {
			Email string `json:"email"`
		} `json:"invitee"`
		ClientID            string         `json:"client_id"`
		ConnectionID        string         `json:"connection_id"`
		TTLSec              *int           `json:"ttl_sec"`
		AppMetadata         map[string]any `json:"app_metadata"`
		UserMetadata        map[string]any `json:"user_metadata"`
		Roles               []string       `json:"roles"`
		SendInvitationEmail *bool          `json:"send_invitation_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}

	if req.Inviter == nil || req.Inviter.Name == "" {
		writeAuth0Error(w, http.StatusBadRequest, "inviter.name is required")
		return
	}
	if req.Invitee == nil || req.Invitee.Email == "" {
		writeAuth0Error(w, http.StatusBadRequest, "invitee.email is required")
		return
	}
	if req.ClientID == "" {
		writeAuth0Error(w, http.StatusBadRequest, "client_id is required")
		return
	}

	// Auth0 schema-validates ttl_sec: 0 or absent means the default, above the
	// maximum is rejected rather than clamped.
	ttlSec := config.InvitationDefaultTTLSec
	if req.TTLSec != nil && *req.TTLSec != 0 {
		ttlSec = *req.TTLSec
		if ttlSec < 0 {
			writeAuth0Error(w, http.StatusBadRequest, "ttl_sec should be >= 0")
			return
		}
		if ttlSec > config.InvitationMaxTTLSec {
			writeAuth0Error(w, http.StatusBadRequest, "ttl_sec should be <= 2592000")
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	org, ok := s.organizations[orgID]
	if !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}

	client, ok := s.clients[req.ClientID]
	if !ok {
		writeAuth0Error(w, http.StatusBadRequest, "client "+req.ClientID+" does not exist")
		return
	}
	// Auth0 400s when the named client has no login initiation endpoint.
	if client.InitiateLoginURI == "" {
		writeAuth0Error(w, http.StatusBadRequest,
			"client "+req.ClientID+" has no initiate_login_uri configured")
		return
	}

	// A named connection must exist, be enabled here, and not be passwordless,
	// else the invitee is forced through a connection the org cannot use.
	if req.ConnectionID != "" {
		conn, ok := s.connections[req.ConnectionID]
		if !ok {
			writeAuth0Error(w, http.StatusBadRequest, "connection "+req.ConnectionID+" does not exist")
			return
		}
		if conn.IsPasswordless() {
			writeAuth0Error(w, http.StatusBadRequest,
				"cannot invite to a passwordless connection: "+conn.Name)
			return
		}
		if !s.isConnectionEnabled(orgID, req.ConnectionID) {
			writeAuth0Error(w, http.StatusBadRequest,
				"connection "+req.ConnectionID+" is not enabled on this organization")
			return
		}
	} else if !s.hasNonPasswordlessConnection(orgID) {
		writeAuth0Error(w, http.StatusBadRequest,
			"organization has no non-passwordless enabled connection to invite to")
		return
	}

	// The mock's member role is a single value, so more than one role cannot
	// be modelled through acceptance. Refuse rather than silently drop.
	if len(req.Roles) > 1 {
		writeAuth0Error(w, http.StatusBadRequest,
			"the auth0 mock models one role per invitation; got "+strconv.Itoa(len(req.Roles)))
		return
	}
	// A role id that names nothing would carry a grant that resolves to
	// nothing on acceptance.
	if unknown := s.unknownRoleIDs(req.Roles); len(unknown) > 0 {
		writeAuth0Error(w, http.StatusBadRequest,
			"unknown role ids: "+strings.Join(unknown, ", "))
		return
	}

	// Build the URL first: a bad initiate_login_uri must fail the request, not
	// yield an invitation whose link cannot be followed.
	ticketID := "tkt_" + s.generateID()
	link, err := invitationURL(client.InitiateLoginURI, ticketID, org, req.ConnectionID)
	if err != nil {
		writeAuth0Error(w, http.StatusBadRequest,
			"client "+req.ClientID+": "+err.Error())
		return
	}

	now := time.Now()
	inv := config.OrganizationInvitation{
		ID:                  "uinv_" + s.generateID(),
		OrganizationID:      orgID,
		InviterName:         req.Inviter.Name,
		InviteeEmail:        req.Invitee.Email,
		ClientID:            req.ClientID,
		ConnectionID:        req.ConnectionID,
		TicketID:            ticketID,
		InvitationURL:       link,
		AppMetadata:         config.AppMetadata(req.AppMetadata).Clone(),
		UserMetadata:        config.AppMetadata(req.UserMetadata).Clone(),
		Roles:               req.Roles,
		SendInvitationEmail: req.SendInvitationEmail == nil || *req.SendInvitationEmail,
		CreatedAt:           now,
		ExpiresAt:           now.Add(time.Duration(ttlSec) * time.Second),
	}
	s.invitations[orgID] = append(s.invitations[orgID], inv)

	if inv.SendInvitationEmail {
		log.Printf("Invitation created for %s in %s (no email sent by the mock): %s",
			inv.InviteeEmail, orgID, inv.InvitationURL)
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(viewInvitation(&inv))
}

func (s *Server) getOrganizationInvitation(w http.ResponseWriter, orgID, invitationID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.organizations[orgID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}

	pending := s.pendingInvitations(orgID, time.Now())
	for i := range pending {
		if pending[i].ID == invitationID {
			_ = json.NewEncoder(w).Encode(viewInvitation(&pending[i]))
			return
		}
	}
	writeAuth0Error(w, http.StatusNotFound, "invitation not found")
}

func (s *Server) deleteOrganizationInvitation(w http.ResponseWriter, orgID, invitationID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.organizations[orgID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}

	// Prune first so revoking an expired invitation 404s regardless of whether
	// an earlier list or read already pruned it.
	s.pendingInvitations(orgID, time.Now())

	stored := s.invitations[orgID]
	for i, inv := range stored {
		if inv.ID != invitationID {
			continue
		}
		s.invitations[orgID] = append(stored[:i:i], stored[i+1:]...)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeAuth0Error(w, http.StatusNotFound, "invitation not found")
}

// invitationURL builds <login_uri>?invitation=<ticket>&organization=<org>
// &organization_name=<name>, which the SPA forwards to loginWithRedirect.
// Parsed rather than concatenated so an existing query survives.
func invitationURL(initiateLoginURI, ticketID string, org *config.Organization, connectionID string) (string, error) {
	u, err := url.Parse(initiateLoginURI)
	if err != nil {
		return "", err
	}
	if err := validateInitiateLoginURI(initiateLoginURI); err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("invitation", ticketID)
	q.Set("organization", org.ID)
	q.Set("organization_name", org.Name)
	// An invitation that forces a connection has to say so in its own link,
	// or the SPA has nothing to forward and the ticket cannot be redeemed.
	if connectionID != "" {
		q.Set("connection", connectionID)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// validateInitiateLoginURI enforces what the Management API requires of the
// field: absolute https with no fragment. go-auth0 states it on the struct
// ("must be https and cannot contain a fragment"), so accepting http or a
// fragment would green-light a client real Auth0 refuses.
func validateInitiateLoginURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("initiate_login_uri is not a valid URL: %w", err)
	}
	// url.Parse accepts relative references, so "/login" parses cleanly.
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("initiate_login_uri must be absolute with a host, got %q", raw)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("initiate_login_uri must be https, got scheme %q", u.Scheme)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("initiate_login_uri cannot contain a fragment, got %q", raw)
	}
	return nil
}
