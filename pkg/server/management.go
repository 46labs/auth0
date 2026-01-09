package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/46labs/auth0/pkg/config"
)

func (s *Server) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		s.listOrganizations(w, r)
	case "POST":
		s.createOrganization(w, r)
	case "OPTIONS":
		return
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleOrganization(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	orgID := strings.TrimPrefix(r.URL.Path, "/api/v2/organizations/")
	if idx := strings.Index(orgID, "/"); idx != -1 {
		orgID = orgID[:idx]
	}

	switch r.Method {
	case "GET":
		s.getOrganization(w, r, orgID)
	case "PATCH":
		s.updateOrganization(w, r, orgID)
	case "DELETE":
		s.deleteOrganization(w, r, orgID)
	case "OPTIONS":
		return
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) listOrganizations(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	orgs := make([]config.Organization, 0, len(s.organizations))
	for _, org := range s.organizations {
		orgs = append(orgs, *org)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"organizations": orgs,
		"start":         0,
		"limit":         50,
		"total":         len(orgs),
	})
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	var org config.Organization
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	if org.Name == "" {
		http.Error(w, `{"error":"name_required"}`, http.StatusBadRequest)
		return
	}

	if org.ID == "" {
		org.ID = "org_" + s.generateID()
	}

	s.mu.Lock()
	s.organizations[org.ID] = &org
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(org)
}

func (s *Server) getOrganization(w http.ResponseWriter, r *http.Request, orgID string) {
	s.mu.RLock()
	org, exists := s.organizations[orgID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, `{"error":"organization_not_found"}`, http.StatusNotFound)
		return
	}

	_ = json.NewEncoder(w).Encode(org)
}

func (s *Server) updateOrganization(w http.ResponseWriter, r *http.Request, orgID string) {
	s.mu.Lock()
	org, exists := s.organizations[orgID]
	if !exists {
		s.mu.Unlock()
		http.Error(w, `{"error":"organization_not_found"}`, http.StatusNotFound)
		return
	}

	var updates config.Organization
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.mu.Unlock()
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	if updates.DisplayName != "" {
		org.DisplayName = updates.DisplayName
	}
	if updates.Branding != nil {
		org.Branding = updates.Branding
	}
	if updates.Metadata != nil {
		if org.Metadata == nil {
			org.Metadata = make(map[string]interface{})
		}
		for k, v := range updates.Metadata {
			org.Metadata[k] = v
		}
	}
	s.mu.Unlock()

	_ = json.NewEncoder(w).Encode(org)
}

func (s *Server) deleteOrganization(w http.ResponseWriter, r *http.Request, orgID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.organizations[orgID]; !exists {
		http.Error(w, `{"error":"organization_not_found"}`, http.StatusNotFound)
		return
	}

	delete(s.organizations, orgID)
	delete(s.members, orgID)

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v2/organizations/"), "/")
	if len(parts) < 2 {
		http.Error(w, `{"error":"invalid_path"}`, http.StatusBadRequest)
		return
	}
	orgID := parts[0]

	switch r.Method {
	case "GET":
		s.listOrganizationMembers(w, r, orgID)
	case "POST":
		s.addOrganizationMember(w, r, orgID)
	case "DELETE":
		s.deleteOrganizationMembers(w, r, orgID)
	case "OPTIONS":
		return
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) listOrganizationMembers(w http.ResponseWriter, r *http.Request, orgID string) {
	s.mu.RLock()
	members, exists := s.members[orgID]
	s.mu.RUnlock()

	if !exists {
		members = []config.OrganizationMember{}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"members": members,
		"start":   0,
		"limit":   50,
		"total":   len(members),
	})
}

func (s *Server) addOrganizationMember(w http.ResponseWriter, r *http.Request, orgID string) {
	var req struct {
		Members []string `json:"members"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate that the organization exists
	if _, exists := s.organizations[orgID]; !exists {
		http.Error(w, `{"error":"organization_not_found"}`, http.StatusNotFound)
		return
	}

	for _, userID := range req.Members {
		// Validate that the user exists
		user, exists := s.users[userID]
		if !exists {
			continue // Skip non-existent users
		}

		// Create the organization member without role (will be assigned separately)
		member := config.OrganizationMember{
			UserID: userID,
			OrgID:  orgID,
			Role:   "", // Role assigned via separate endpoint
		}

		// Add to organization's member list
		s.members[orgID] = append(s.members[orgID], member)

		// Update user's organization list
		if user.Organizations == nil {
			user.Organizations = []string{}
		}
		// Avoid duplicate organization entries
		hasOrg := false
		for _, existingOrgID := range user.Organizations {
			if existingOrgID == orgID {
				hasOrg = true
				break
			}
		}
		if !hasOrg {
			user.Organizations = append(user.Organizations, orgID)
		}
	}

	// Return 204 No Content (Auth0 API behavior for AddMembers)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteOrganizationMembers(w http.ResponseWriter, r *http.Request, orgID string) {
	var req struct {
		Members []string `json:"members"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate that the organization exists
	if _, exists := s.organizations[orgID]; !exists {
		http.Error(w, `{"error":"organization_not_found"}`, http.StatusNotFound)
		return
	}

	// Remove members from organization
	for _, userID := range req.Members {
		// Remove from organization's member list
		if members, exists := s.members[orgID]; exists {
			filtered := make([]config.OrganizationMember, 0)
			for _, member := range members {
				if member.UserID != userID {
					filtered = append(filtered, member)
				}
			}
			s.members[orgID] = filtered
		}

		// Remove organization from user's organization list
		if user, exists := s.users[userID]; exists && user.Organizations != nil {
			filtered := make([]string, 0)
			for _, existingOrgID := range user.Organizations {
				if existingOrgID != orgID {
					filtered = append(filtered, existingOrgID)
				}
			}
			user.Organizations = filtered
		}
	}

	// Return 204 No Content (Auth0 API behavior for DeleteMembers)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		s.listConnections(w, r)
	case "POST":
		s.createConnection(w, r)
	case "OPTIONS":
		return
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) listConnections(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	conns := make([]config.Connection, 0, len(s.connections))
	for _, conn := range s.connections {
		conns = append(conns, *conn)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"connections": conns,
		"start":       0,
		"limit":       50,
		"total":       len(conns),
	})
}

func (s *Server) createConnection(w http.ResponseWriter, r *http.Request) {
	var conn config.Connection
	if err := json.NewDecoder(r.Body).Decode(&conn); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	if conn.Name == "" || conn.Strategy == "" {
		http.Error(w, `{"error":"name_and_strategy_required"}`, http.StatusBadRequest)
		return
	}

	if conn.ID == "" {
		conn.ID = "con_" + s.generateID()
	}

	s.mu.Lock()
	s.connections[conn.ID] = &conn
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(conn)
}

func (s *Server) handleOrganizationMemberRoles(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	// Parse path: /api/v2/organizations/:id/members/:memberID/roles
	path := strings.TrimPrefix(r.URL.Path, "/api/v2/organizations/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, `{"error":"invalid_path"}`, http.StatusBadRequest)
		return
	}
	orgID := parts[0]
	memberID := parts[2]

	switch r.Method {
	case "POST":
		s.assignMemberRoles(w, r, orgID, memberID)
	case "DELETE":
		s.deleteMemberRoles(w, r, orgID, memberID)
	case "OPTIONS":
		return
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) assignMemberRoles(w http.ResponseWriter, r *http.Request, orgID, memberID string) {
	var req struct {
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate organization exists
	if _, exists := s.organizations[orgID]; !exists {
		http.Error(w, `{"error":"organization_not_found"}`, http.StatusNotFound)
		return
	}

	// Validate user exists
	if _, exists := s.users[memberID]; !exists {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	// Find and update the member's role
	members, exists := s.members[orgID]
	if !exists {
		http.Error(w, `{"error":"member_not_found"}`, http.StatusNotFound)
		return
	}

	found := false
	for i := range members {
		if members[i].UserID == memberID {
			// Use the first role from the array
			if len(req.Roles) > 0 {
				members[i].Role = req.Roles[0]
			}
			found = true
			break
		}
	}

	if !found {
		http.Error(w, `{"error":"member_not_found_in_organization"}`, http.StatusNotFound)
		return
	}

	// Update the storage
	s.members[orgID] = members

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteMemberRoles(w http.ResponseWriter, r *http.Request, orgID, memberID string) {
	// For mock purposes, we'll just clear the role
	s.mu.Lock()
	defer s.mu.Unlock()

	members, exists := s.members[orgID]
	if !exists {
		http.Error(w, `{"error":"organization_not_found"}`, http.StatusNotFound)
		return
	}

	for i := range members {
		if members[i].UserID == memberID {
			members[i].Role = ""
			s.members[orgID] = members
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	http.Error(w, `{"error":"member_not_found"}`, http.StatusNotFound)
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	userID := strings.TrimPrefix(r.URL.Path, "/api/v2/users/")

	switch r.Method {
	case "GET":
		s.getUser(w, r, userID)
	case "PATCH":
		s.updateUser(w, r, userID)
	case "OPTIONS":
		return
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, userID string) {
	user := s.getUserByID(userID)
	if user == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	_ = json.NewEncoder(w).Encode(user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, userID string) {
	var updates struct {
		AppMetadata  *config.AppMetadata    `json:"app_metadata"`
		UserMetadata map[string]interface{} `json:"user_metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	if err := s.updateUserMetadata(userID, updates.AppMetadata, updates.UserMetadata); err != nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	user := s.getUserByID(userID)
	_ = json.NewEncoder(w).Encode(user)
}
