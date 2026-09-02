package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
)

// auth0TimeFormat is the ISO 8601 rendering the Management API uses for
// created_at / expires_at.
const auth0TimeFormat = "2006-01-02T15:04:05.000Z"

// invitationView is the wire shape of an organization invitation. Auth0 nests
// the inviter and invitee as objects and reports the window as expires_at, not
// as the ttl_sec that was sent in.
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

// pendingInvitations returns the organization's unexpired invitations and
// prunes the expired ones. Auth0 lets an invitation lapse on its TTL rather
// than reporting it as pending. Callers must hold the write lock.
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

	// ttl_sec is schema-validated by Auth0: 0 or absent means the default, and
	// anything above the maximum is rejected rather than clamped.
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
	// Auth0 resolves invitation_url against the application's login initiation
	// endpoint and 400s when the client has none configured.
	if client.InitiateLoginURI == "" {
		writeAuth0Error(w, http.StatusBadRequest,
			"client "+req.ClientID+" has no initiate_login_uri configured")
		return
	}

	// A named connection must exist, be enabled on this organization, and not
	// be passwordless. Skipping the enabled check would mint an invitation
	// that forces the invitee through a connection the organization cannot
	// authenticate against.
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
		// Without a named connection Auth0 needs some non-passwordless
		// connection on the organization for the invitee to authenticate with.
		writeAuth0Error(w, http.StatusBadRequest,
			"organization has no non-passwordless enabled connection to invite to")
		return
	}

	// Build the URL before storing anything: an unparseable
	// initiate_login_uri must fail the request, not yield an invitation whose
	// link cannot be followed.
	ticketID := "tkt_" + s.generateID()
	link, err := invitationURL(client.InitiateLoginURI, ticketID, org)
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

	// Prune first, so revoking an already-expired invitation 404s regardless of
	// whether a list or read happened to prune it earlier.
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

// invitationURL builds the link the invitee follows. Auth0 points it at the
// application's login initiation endpoint and carries the ticket, the
// organization id and its name, which is what lets the SPA forward them to
// loginWithRedirect.
//
// The URI is parsed rather than concatenated: a hash-routed SPA login URI
// (https://app.test/#/login) would otherwise get the parameters appended
// inside the fragment, where the browser never exposes them as query values.
func invitationURL(initiateLoginURI, ticketID string, org *config.Organization) (string, error) {
	u, err := url.Parse(initiateLoginURI)
	if err != nil {
		return "", err
	}
	// url.Parse accepts relative references, so "/login" parses cleanly and
	// would yield a link that is not rooted at the application at all.
	if !u.IsAbs() || u.Host == "" {
		return "", fmt.Errorf("initiate_login_uri must be absolute with a host, got %q", initiateLoginURI)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("initiate_login_uri must be http or https, got scheme %q", u.Scheme)
	}

	q := u.Query()
	q.Set("invitation", ticketID)
	q.Set("organization", org.ID)
	q.Set("organization_name", org.Name)
	u.RawQuery = q.Encode()

	// url.URL.String orders the query before the fragment, so a fragment in
	// the configured URI stays last.
	return u.String(), nil
}
