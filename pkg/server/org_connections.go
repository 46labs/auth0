package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/46labs/auth0/pkg/config"
)

// orgConnectionView is the wire shape: the stored pairing plus the
// connection's name and strategy, which Auth0 nests under "connection".
type orgConnectionView struct {
	ConnectionID            string                `json:"connection_id"`
	AssignMembershipOnLogin bool                  `json:"assign_membership_on_login"`
	IsSignupEnabled         bool                  `json:"is_signup_enabled"`
	ShowAsButton            bool                  `json:"show_as_button"`
	Connection              *orgConnectionDetails `json:"connection,omitempty"`
}

type orgConnectionDetails struct {
	Name     string `json:"name"`
	Strategy string `json:"strategy"`
}

// viewOrgConnection requires the caller to hold at least a read lock.
func (s *Server) viewOrgConnection(oc config.OrganizationConnection) orgConnectionView {
	view := orgConnectionView{
		ConnectionID:            oc.ConnectionID,
		AssignMembershipOnLogin: oc.AssignMembershipOnLogin,
		IsSignupEnabled:         oc.IsSignupEnabled,
		ShowAsButton:            oc.ShowAsButton,
	}
	if conn, ok := s.connections[oc.ConnectionID]; ok {
		view.Connection = &orgConnectionDetails{Name: conn.Name, Strategy: conn.Strategy}
	}
	return view
}

// handleOrganizationConnections serves the enabled_connections collection:
// GET /api/v2/organizations/{id}/enabled_connections and POST to add one.
func (s *Server) handleOrganizationConnections(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	orgID := orgIDFromPath(r.URL.Path)

	switch r.Method {
	case http.MethodGet:
		s.listOrganizationConnections(w, r, orgID)
	case http.MethodPost:
		s.addOrganizationConnection(w, r, orgID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleOrganizationConnection serves a single enabled connection:
// GET, PATCH and DELETE on .../enabled_connections/{connectionID}.
func (s *Server) handleOrganizationConnection(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	orgID := orgIDFromPath(r.URL.Path)
	segments := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/organizations/"), "/"), "/")
	connectionID := segments[len(segments)-1]

	switch r.Method {
	case http.MethodGet:
		s.getOrganizationConnection(w, orgID, connectionID)
	case http.MethodPatch:
		s.updateOrganizationConnection(w, r, orgID, connectionID)
	case http.MethodDelete:
		s.deleteOrganizationConnection(w, orgID, connectionID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listOrganizationConnections(w http.ResponseWriter, r *http.Request, orgID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.organizations[orgID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}

	pairings := s.orgConnections[orgID]
	lo, hi, window := paginate(r, len(pairings))
	page := pairings[lo:hi]

	views := make([]orgConnectionView, 0, len(page))
	for _, oc := range page {
		views = append(views, s.viewOrgConnection(oc))
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled_connections": views,
		"start":               window.Start,
		"limit":               window.Limit,
		"length":              len(views),
		"total":               window.Total,
	})
}

func (s *Server) addOrganizationConnection(w http.ResponseWriter, r *http.Request, orgID string) {
	var req struct {
		ConnectionID            string `json:"connection_id"`
		AssignMembershipOnLogin *bool  `json:"assign_membership_on_login"`
		IsSignupEnabled         *bool  `json:"is_signup_enabled"`
		ShowAsButton            *bool  `json:"show_as_button"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ConnectionID == "" {
		writeAuth0Error(w, http.StatusBadRequest, "connection_id is required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.organizations[orgID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}
	if _, ok := s.connections[req.ConnectionID]; !ok {
		writeAuth0Error(w, http.StatusBadRequest, "connection "+req.ConnectionID+" does not exist")
		return
	}
	for _, existing := range s.orgConnections[orgID] {
		if existing.ConnectionID == req.ConnectionID {
			writeAuth0Error(w, http.StatusConflict, "connection is already enabled on this organization")
			return
		}
	}

	oc := config.OrganizationConnection{
		OrgID:        orgID,
		ConnectionID: req.ConnectionID,
	}
	if req.AssignMembershipOnLogin != nil {
		oc.AssignMembershipOnLogin = *req.AssignMembershipOnLogin
	}
	if req.IsSignupEnabled != nil {
		oc.IsSignupEnabled = *req.IsSignupEnabled
	}
	// Auth0 defaults show_as_button to true.
	oc.ShowAsButton = true
	if req.ShowAsButton != nil {
		oc.ShowAsButton = *req.ShowAsButton
	}

	if err := validOrgConnection(oc); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.orgConnections[orgID] = append(s.orgConnections[orgID], oc)

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(s.viewOrgConnection(oc))
}

func (s *Server) getOrganizationConnection(w http.ResponseWriter, orgID, connectionID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.organizations[orgID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}
	for _, oc := range s.orgConnections[orgID] {
		if oc.ConnectionID == connectionID {
			_ = json.NewEncoder(w).Encode(s.viewOrgConnection(oc))
			return
		}
	}
	writeAuth0Error(w, http.StatusNotFound, "connection is not enabled on this organization")
}

func (s *Server) updateOrganizationConnection(w http.ResponseWriter, r *http.Request, orgID, connectionID string) {
	var req struct {
		AssignMembershipOnLogin *bool `json:"assign_membership_on_login"`
		IsSignupEnabled         *bool `json:"is_signup_enabled"`
		ShowAsButton            *bool `json:"show_as_button"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.organizations[orgID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}

	pairings := s.orgConnections[orgID]
	for i := range pairings {
		if pairings[i].ConnectionID != connectionID {
			continue
		}
		// Apply to a copy so a rejected patch leaves the stored pairing alone.
		updated := pairings[i]
		if req.AssignMembershipOnLogin != nil {
			updated.AssignMembershipOnLogin = *req.AssignMembershipOnLogin
		}
		if req.IsSignupEnabled != nil {
			updated.IsSignupEnabled = *req.IsSignupEnabled
		}
		if req.ShowAsButton != nil {
			updated.ShowAsButton = *req.ShowAsButton
		}
		if err := validOrgConnection(updated); err != nil {
			writeAuth0Error(w, http.StatusBadRequest, err.Error())
			return
		}

		pairings[i] = updated
		_ = json.NewEncoder(w).Encode(s.viewOrgConnection(pairings[i]))
		return
	}
	writeAuth0Error(w, http.StatusNotFound, "connection is not enabled on this organization")
}

func (s *Server) deleteOrganizationConnection(w http.ResponseWriter, orgID, connectionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.organizations[orgID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "organization not found")
		return
	}

	pairings := s.orgConnections[orgID]
	for i, oc := range pairings {
		if oc.ConnectionID == connectionID {
			s.orgConnections[orgID] = append(pairings[:i:i], pairings[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	writeAuth0Error(w, http.StatusNotFound, "connection is not enabled on this organization")
}

// isConnectionEnabled requires the caller to hold the lock.
func (s *Server) isConnectionEnabled(orgID, connectionID string) bool {
	for _, oc := range s.orgConnections[orgID] {
		if oc.ConnectionID == connectionID {
			return true
		}
	}
	return false
}

// validOrgConnection rejects pairings Auth0 disallows. Validating the
// resulting state, not the request fields, is what stops a PATCH of either
// field alone from reaching the invalid combination.
func validOrgConnection(oc config.OrganizationConnection) error {
	if oc.IsSignupEnabled && !oc.AssignMembershipOnLogin {
		return errSignupWithoutMembership
	}
	return nil
}

var errSignupWithoutMembership = errors.New(
	"is_signup_enabled requires assign_membership_on_login to be true")

// hasNonPasswordlessConnection reports whether the org has one, which Auth0
// requires before an invitation may be created. Caller holds the lock.
func (s *Server) hasNonPasswordlessConnection(orgID string) bool {
	for _, oc := range s.orgConnections[orgID] {
		conn, ok := s.connections[oc.ConnectionID]
		if ok && !conn.IsPasswordless() {
			return true
		}
	}
	return false
}

// orgIDFromPath extracts the id from /api/v2/organizations/{id}/...
func orgIDFromPath(path string) string {
	rest := strings.TrimPrefix(path, "/api/v2/organizations/")
	if idx := strings.Index(rest, "/"); idx != -1 {
		return rest[:idx]
	}
	return rest
}
