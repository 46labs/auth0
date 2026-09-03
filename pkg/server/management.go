package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/46labs/auth0/pkg/config"
)

// Management API pagination defaults, matching Auth0's list endpoints.
const (
	defaultPerPage = 50
	maxPerPage     = 100
)

// listWindow is the envelope alongside a page. The SDK's HasNext compares
// total > start+limit, so these values decide whether a caller stops paging.
type listWindow struct {
	Start int
	Limit int
	Total int
}

// paginate resolves page/per_page against a collection size, returning
// half-open [lo, hi) bounds and the response envelope. Ignoring them would
// serve page 0 forever to a caller paging until an empty result, which is what
// the SDK tells invitation callers to do.
func paginate(r *http.Request, total int) (lo, hi int, window listWindow) {
	perPage := defaultPerPage
	if v := r.URL.Query().Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			perPage = min(n, maxPerPage)
		}
	}

	page := 0
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}

	// Clamp before multiplying: a huge page would overflow int and yield a
	// negative lower bound, panicking the slice. perPage is always >= 1.
	if maxPage := total/perPage + 1; page > maxPage {
		page = maxPage
	}

	lo = min(page*perPage, total)
	hi = min(lo+perPage, total)
	return lo, hi, listWindow{Start: lo, Limit: perPage, Total: total}
}

// writeList renders a page. Auth0 returns a bare array unless
// include_totals=true; go-auth0 always sets it, so SDK callers get the
// envelope and raw callers get what the API actually returns.
func writeList(w http.ResponseWriter, r *http.Request, key string, items any, window listWindow, length int) {
	if r.URL.Query().Get("include_totals") != "true" {
		_ = json.NewEncoder(w).Encode(items)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		key:      items,
		"start":  window.Start,
		"limit":  window.Limit,
		"length": length,
		"total":  window.Total,
	})
}

// writeAuth0Error renders the Management API's error shape, which the SDK
// decodes into a management.Error.
func writeAuth0Error(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"statusCode": status,
		"error":      http.StatusText(status),
		"message":    message,
	})
}

// routeOrganizationPath dispatches /api/v2/organizations/{id} and its
// subresources. An unrecognized subresource must 404: the previous router fell
// through to the bare-organization handlers, which truncate the path at the
// first slash, so a DELETE on .../invitations/{iid} deleted the organization
// itself and answered 204.
func (s *Server) routeOrganizationPath(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/organizations/")

	if strings.HasPrefix(rest, "name/") {
		s.handleOrganizationByName(w, r)
		return
	}

	// segments[0] is the organization id; the rest name the subresource.
	segments := strings.Split(strings.Trim(rest, "/"), "/")

	switch {
	case len(segments) == 1:
		s.handleOrganization(w, r)
	case len(segments) == 2 && segments[1] == "members":
		s.handleOrganizationMembers(w, r)
	case len(segments) == 4 && segments[1] == "members" && segments[3] == "roles":
		s.handleOrganizationMemberRoles(w, r)
	case len(segments) == 2 && segments[1] == "enabled_connections":
		s.handleOrganizationConnections(w, r)
	case len(segments) == 3 && segments[1] == "enabled_connections":
		s.handleOrganizationConnection(w, r)
	case len(segments) == 2 && segments[1] == "invitations":
		s.handleOrganizationInvitations(w, r)
	case len(segments) == 3 && segments[1] == "invitations":
		s.handleOrganizationInvitation(w, r)
	default:
		s.setCORS(w, r)
		if r.Method == http.MethodOptions {
			return
		}
		writeAuth0Error(w, http.StatusNotFound, "route not implemented by the auth0 mock: "+r.URL.Path)
	}
}

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

	all := make([]config.Organization, 0, len(s.organizations))
	for _, org := range s.organizations {
		all = append(all, *org.Clone())
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	lo, hi, window := paginate(r, len(all))
	orgs := all[lo:hi]

	writeList(w, r, "organizations", orgs, window, len(orgs))
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	// enabled_connections rides along on organization creation. Dropping it
	// would answer 201 with an org that has no connections, so an immediate
	// invitation would fail for an invisible reason.
	var req struct {
		config.Organization
		EnabledConnections []struct {
			ConnectionID            string `json:"connection_id"`
			AssignMembershipOnLogin *bool  `json:"assign_membership_on_login"`
			IsSignupEnabled         *bool  `json:"is_signup_enabled"`
			ShowAsButton            *bool  `json:"show_as_button"`
		} `json:"enabled_connections"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	org := req.Organization
	if org.Name == "" {
		http.Error(w, `{"error":"name_required"}`, http.StatusBadRequest)
		return
	}

	if org.ID == "" {
		org.ID = "org_" + s.generateID()
	}

	// Store a copy: the response below must not share memory with the record
	// a concurrent PATCH could be mutating.
	stored := org.Clone()

	s.mu.Lock()
	pairings := make([]config.OrganizationConnection, 0, len(req.EnabledConnections))
	for _, ec := range req.EnabledConnections {
		if ec.ConnectionID == "" {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusBadRequest, "enabled_connections[].connection_id is required")
			return
		}
		if _, ok := s.connections[ec.ConnectionID]; !ok {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusBadRequest, "connection "+ec.ConnectionID+" does not exist")
			return
		}
		// Two pairings for one connection would leave DeleteConnection
		// removing only the first while answering 204.
		for _, existing := range pairings {
			if existing.ConnectionID == ec.ConnectionID {
				s.mu.Unlock()
				writeAuth0Error(w, http.StatusBadRequest,
					"connection "+ec.ConnectionID+" is listed twice in enabled_connections")
				return
			}
		}

		oc := config.OrganizationConnection{
			OrgID:        org.ID,
			ConnectionID: ec.ConnectionID,
			ShowAsButton: true,
		}
		if ec.AssignMembershipOnLogin != nil {
			oc.AssignMembershipOnLogin = *ec.AssignMembershipOnLogin
		}
		if ec.IsSignupEnabled != nil {
			oc.IsSignupEnabled = *ec.IsSignupEnabled
		}
		if ec.ShowAsButton != nil {
			oc.ShowAsButton = *ec.ShowAsButton
		}
		if err := validOrgConnection(oc); err != nil {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusBadRequest, err.Error())
			return
		}
		pairings = append(pairings, oc)
	}

	s.organizations[stored.ID] = stored
	views := make([]orgConnectionView, 0, len(pairings))
	if len(pairings) > 0 {
		s.orgConnections[org.ID] = pairings
		for _, oc := range pairings {
			views = append(views, s.viewOrgConnection(oc))
		}
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	// Auth0's create response carries the projected pairings, so the SDK's
	// hydrated Organization comes back with server defaults applied.
	if len(views) > 0 {
		body, err := json.Marshal(org)
		if err == nil {
			var merged map[string]any
			if json.Unmarshal(body, &merged) == nil {
				merged["enabled_connections"] = views
				_ = json.NewEncoder(w).Encode(merged)
				return
			}
		}
	}
	_ = json.NewEncoder(w).Encode(org)
}

func (s *Server) getOrganization(w http.ResponseWriter, r *http.Request, orgID string) {
	s.mu.RLock()
	org, exists := s.organizations[orgID]
	if exists {
		org = org.Clone()
	}
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
	response := org.Clone()
	s.mu.Unlock()

	_ = json.NewEncoder(w).Encode(response)
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
	delete(s.orgConnections, orgID)
	delete(s.invitations, orgID)

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

// handleOrganizationByName serves GET /api/v2/organizations/name/{name},
// the SDK's Organization.ReadByName. Returns the org record by its machine
// name. Used by pee's EnsureOrganization to skip the create when the org
// already exists.
func (s *Server) handleOrganizationByName(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "GET" {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/v2/organizations/name/")
	if idx := strings.Index(name, "/"); idx != -1 {
		name = name[:idx]
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, org := range s.organizations {
		if org.Name == name {
			_ = json.NewEncoder(w).Encode(org.Clone())
			return
		}
	}
	http.Error(w, `{"statusCode":404,"error":"Not Found","message":"organization not found"}`, http.StatusNotFound)
}

// handleUserOrganizations serves GET /api/v2/users/{id}/organizations, the
// SDK's User.Organizations. Returns every org the user is a current member of.
// Source of truth is the s.members map (kept in sync by AddOrganizationMember).
func (s *Server) handleUserOrganizations(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "GET" {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/users/")
	userID := strings.TrimSuffix(rest, "/organizations")

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, exists := s.users[userID]; !exists {
		http.Error(w, `{"statusCode":404,"error":"Not Found","message":"user not found"}`, http.StatusNotFound)
		return
	}

	orgs := make([]config.Organization, 0)
	for orgID, members := range s.members {
		for _, m := range members {
			if m.UserID != userID {
				continue
			}
			if org, ok := s.organizations[orgID]; ok {
				orgs = append(orgs, *org.Clone())
			}
			break
		}
	}

	sort.Slice(orgs, func(i, j int) bool { return orgs[i].ID < orgs[j].ID })

	lo, hi, window := paginate(r, len(orgs))
	page := orgs[lo:hi]

	writeList(w, r, "organizations", page, window, len(page))
}

func (s *Server) listOrganizationMembers(w http.ResponseWriter, r *http.Request, orgID string) {
	// held across the member/user join below
	s.mu.RLock()
	defer s.mu.RUnlock()

	members, exists := s.members[orgID]
	if !exists {
		members = []config.OrganizationMember{}
	}

	// Transform to SDK-compatible format
	responseMembers := make([]map[string]interface{}, 0, len(members))
	for _, member := range members {
		user, userExists := s.users[member.UserID]
		responseMember := map[string]interface{}{
			"user_id": member.UserID,
		}

		// Add user fields if available
		if userExists {
			if user.Name != "" {
				responseMember["name"] = user.Name
			}
			if user.Email != "" {
				responseMember["email"] = user.Email
			}
			if user.Picture != "" {
				responseMember["picture"] = user.Picture
			}
		}

		// The member role is a name; pair it with the registry's id so the
		// SDK's role objects carry both.
		if member.Role != "" {
			id := s.roleIDByName(member.Role)
			if id == "" {
				id = member.Role
			}
			responseMember["roles"] = []map[string]interface{}{
				{"id": id, "name": member.Role},
			}
		}

		responseMembers = append(responseMembers, responseMember)
	}

	lo, hi, window := paginate(r, len(responseMembers))
	page := responseMembers[lo:hi]

	writeList(w, r, "members", page, window, len(page))
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

		alreadyMember := false
		for _, existingMember := range s.members[orgID] {
			if existingMember.UserID == userID {
				alreadyMember = true
				break
			}
		}
		if alreadyMember {
			continue
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

	all := make([]config.Connection, 0, len(s.connections))
	for _, conn := range s.connections {
		all = append(all, *conn.Clone())
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	lo, hi, window := paginate(r, len(all))
	conns := all[lo:hi]

	writeList(w, r, "connections", conns, window, len(conns))
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

	stored := conn.Clone()
	s.mu.Lock()
	s.connections[stored.ID] = stored
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

	// Auth0 takes role ids here. The mock's member role is a single value, so
	// more than one cannot be modelled — say so rather than drop the rest.
	if len(req.Roles) > 1 {
		writeAuth0Error(w, http.StatusBadRequest,
			"the auth0 mock models one role per member; got "+strconv.Itoa(len(req.Roles)))
		return
	}
	// Auth0 takes role ids. This accepts a name too: the mock's own config
	// seeds members by role name and pkg/client passes one, and tightening
	// that is a change to this repo's helper API, not to Auth0 parity. The
	// invitation path, which the onboarding design does exercise, is strict.
	roleName := ""
	if len(req.Roles) > 0 {
		roleName = s.roleNameByID(req.Roles[0])
		if roleName == "" {
			roleName = req.Roles[0]
		}
	}

	found := false
	for i := range members {
		if members[i].UserID == memberID {
			if roleName != "" {
				members[i].Role = roleName
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

	// Update user's AppMetadata with tenant_id and role for JWT claims
	if user, exists := s.users[memberID]; exists {
		if user.AppMetadata == nil {
			user.AppMetadata = config.AppMetadata{}
		}
		user.AppMetadata[config.AppMetaTenantID] = orgID
		if roleName != "" {
			user.AppMetadata[config.AppMetaRole] = roleName
		}
		s.users[memberID] = user
	}

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
	case "DELETE":
		s.deleteUser(w, r, userID)
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
		Name         *string                `json:"name"`
		Email        *string                `json:"email"`
		AppMetadata  *config.AppMetadata    `json:"app_metadata"`
		UserMetadata map[string]interface{} `json:"user_metadata"`
		Blocked      *bool                  `json:"blocked"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	// Update basic user fields if provided
	s.mu.Lock()
	user, exists := s.users[userID]
	if !exists {
		s.mu.Unlock()
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	if updates.Name != nil {
		user.Name = *updates.Name
	}
	if updates.Email != nil {
		user.Email = *updates.Email
	}
	s.mu.Unlock()

	// Update metadata and blocked status
	if err := s.updateUserMetadata(userID, updates.AppMetadata, updates.UserMetadata, updates.Blocked); err != nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	updatedUser := s.getUserByID(userID)
	_ = json.NewEncoder(w).Encode(updatedUser)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[userID]; !exists {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	// Remove user from all organizations
	for orgID, members := range s.members {
		filtered := []config.OrganizationMember{}
		for _, member := range members {
			if member.UserID != userID {
				filtered = append(filtered, member)
			}
		}
		s.members[orgID] = filtered
	}

	// Delete the user
	delete(s.users, userID)

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		s.listClients(w, r)
	case "POST":
		s.createClient(w, r)
	case "OPTIONS":
		return
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleClient(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	clientID := strings.TrimPrefix(r.URL.Path, "/api/v2/clients/")

	switch r.Method {
	case "GET":
		s.getClient(w, r, clientID)
	case "PATCH":
		s.updateClient(w, r, clientID)
	case "DELETE":
		s.deleteClient(w, r, clientID)
	case "OPTIONS":
		return
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]config.Client, 0, len(s.clients))
	for _, client := range s.clients {
		all = append(all, *client.Clone())
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ClientID < all[j].ClientID })

	lo, hi, window := paginate(r, len(all))
	clients := all[lo:hi]

	writeList(w, r, "clients", clients, window, len(clients))
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var client config.Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	if client.Name == "" {
		http.Error(w, `{"error":"name_required"}`, http.StatusBadRequest)
		return
	}
	if client.InitiateLoginURI != "" {
		if err := validateInitiateLoginURI(client.InitiateLoginURI); err != nil {
			writeAuth0Error(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if client.ClientID == "" {
		client.ClientID = s.generateID()
	}

	// Generate client_secret for M2M apps
	if client.AppType == "non_interactive" || (client.AppType == "" && len(client.GrantTypes) > 0) {
		for _, gt := range client.GrantTypes {
			if gt == "client_credentials" {
				client.ClientSecret = "secret_" + s.generateID()
				break
			}
		}
	}

	stored := client.Clone()
	s.mu.Lock()
	s.clients[stored.ClientID] = stored
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(client)
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request, clientID string) {
	s.mu.RLock()
	client, exists := s.clients[clientID]
	if exists {
		client = client.Clone()
	}
	s.mu.RUnlock()

	if !exists {
		http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
		return
	}

	_ = json.NewEncoder(w).Encode(client)
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request, clientID string) {
	s.mu.Lock()
	client, exists := s.clients[clientID]
	if !exists {
		s.mu.Unlock()
		http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
		return
	}

	// Pointers distinguish absent from present-and-empty, so a PATCH can
	// clear a value. Mirrors the SDK's client patch shape.
	var updates struct {
		Name             *string         `json:"name"`
		Description      *string         `json:"description"`
		AppType          *string         `json:"app_type"`
		Callbacks        *[]string       `json:"callbacks"`
		GrantTypes       *[]string       `json:"grant_types"`
		JWTConfig        *map[string]any `json:"jwt_configuration"`
		InitiateLoginURI *string         `json:"initiate_login_uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.mu.Unlock()
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}

	// Validate the whole patch before applying any of it: a rejected request
	// must not leave earlier fields written.
	if updates.Name != nil && *updates.Name == "" {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusBadRequest, "name cannot be empty")
		return
	}
	if updates.InitiateLoginURI != nil && *updates.InitiateLoginURI != "" {
		if err := validateInitiateLoginURI(*updates.InitiateLoginURI); err != nil {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if updates.Name != nil {
		client.Name = *updates.Name
	}
	if updates.Description != nil {
		client.Description = *updates.Description
	}
	if updates.AppType != nil {
		client.AppType = *updates.AppType
	}
	if updates.Callbacks != nil {
		client.Callbacks = *updates.Callbacks
	}
	if updates.GrantTypes != nil {
		client.GrantTypes = *updates.GrantTypes
	}
	if updates.JWTConfig != nil {
		client.JWTConfig = *updates.JWTConfig
	}
	if updates.InitiateLoginURI != nil {
		client.InitiateLoginURI = *updates.InitiateLoginURI
	}
	response := client.Clone()
	s.mu.Unlock()

	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[clientID]; !exists {
		http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
		return
	}

	delete(s.clients, clientID)

	w.WriteHeader(http.StatusNoContent)
}
