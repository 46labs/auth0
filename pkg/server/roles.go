package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/46labs/auth0/pkg/config"
)

// handleRoles serves the roles collection: GET /api/v2/roles and POST to
// create one. PEE resolves its admin carrier role at runtime by name, so
// nothing pins a literal role id.
func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.listRoles(w, r)
	case http.MethodPost:
		s.createRole(w, r)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleRole serves a single role by id. Subresources this mock does not
// implement (permissions, users) must 404: truncating the path at the slash
// would dispatch DELETE .../roles/{id}/permissions to deleteRole and destroy
// the role itself, the same fall-through the organization router had.
func (s *Server) handleRole(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	segments := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/roles/"), "/"), "/")
	if len(segments) != 1 || segments[0] == "" {
		if r.Method == http.MethodOptions {
			return
		}
		writeAuth0Error(w, http.StatusNotFound, "route not implemented by the auth0 mock: "+r.URL.Path)
		return
	}
	roleID := segments[0]

	switch r.Method {
	case http.MethodGet:
		s.getRole(w, roleID)
	case http.MethodPatch:
		s.updateRole(w, r, roleID)
	case http.MethodDelete:
		s.deleteRole(w, roleID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// name_filter is a case-insensitive substring match, which is how
	// read-or-create by name resolves an existing role.
	filter := strings.ToLower(r.URL.Query().Get("name_filter"))

	all := make([]config.Role, 0, len(s.roles))
	for _, role := range s.roles {
		if filter != "" && !strings.Contains(strings.ToLower(role.Name), filter) {
			continue
		}
		all = append(all, *role)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })

	lo, hi, window := paginate(r, len(all))
	page := all[lo:hi]

	writeList(w, r, "roles", page, window, len(page))
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	var req config.Role
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" {
		writeAuth0Error(w, http.StatusBadRequest, "name is required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.roles {
		if strings.EqualFold(existing.Name, req.Name) {
			writeAuth0Error(w, http.StatusConflict, "a role named "+req.Name+" already exists")
			return
		}
	}

	// Ids are server-generated. Honoring a caller-supplied one would let a
	// POST overwrite an existing role and slip past the duplicate-name check.
	req.ID = "rol_" + s.generateID()
	stored := req
	s.roles[stored.ID] = &stored

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(req)
}

func (s *Server) getRole(w http.ResponseWriter, roleID string) {
	s.mu.RLock()
	role, ok := s.roles[roleID]
	if ok {
		copied := *role
		role = &copied
	}
	s.mu.RUnlock()

	if !ok {
		writeAuth0Error(w, http.StatusNotFound, "role not found")
		return
	}
	_ = json.NewEncoder(w).Encode(role)
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request, roleID string) {
	var updates struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	role, ok := s.roles[roleID]
	if !ok {
		writeAuth0Error(w, http.StatusNotFound, "role not found")
		return
	}
	if updates.Name != nil {
		if *updates.Name == "" {
			writeAuth0Error(w, http.StatusBadRequest, "name cannot be empty")
			return
		}
		for id, existing := range s.roles {
			if id != roleID && strings.EqualFold(existing.Name, *updates.Name) {
				writeAuth0Error(w, http.StatusConflict, "a role named "+*updates.Name+" already exists")
				return
			}
		}
		// Members store the role name, so a rename has to follow through or
		// their assignments go stale.
		for orgID, members := range s.members {
			for i := range members {
				if members[i].Role == role.Name {
					members[i].Role = *updates.Name
				}
			}
			s.members[orgID] = members
		}
		role.Name = *updates.Name
	}
	if updates.Description != nil {
		role.Description = *updates.Description
	}

	copied := *role
	_ = json.NewEncoder(w).Encode(&copied)
}

func (s *Server) deleteRole(w http.ResponseWriter, roleID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	role, ok := s.roles[roleID]
	if !ok {
		writeAuth0Error(w, http.StatusNotFound, "role not found")
		return
	}

	// Auth0 drops the role from its members; leaving the name behind would
	// keep granting a role that no longer exists.
	for orgID, members := range s.members {
		for i := range members {
			if members[i].Role == role.Name {
				members[i].Role = ""
			}
		}
		s.members[orgID] = members
	}

	delete(s.roles, roleID)

	// Auth0 answers 200 with a body here, not 204; go-auth0 passes a decode
	// destination for exactly that reason.
	_ = json.NewEncoder(w).Encode(struct{}{})
}

// roleNameByID resolves a role id to its name. Invitations carry role ids,
// but the Post-Login Action seeds app_metadata.org_roles with the name, so the
// member role stored on acceptance is the name. Caller holds the lock.
func (s *Server) roleNameByID(id string) string {
	if role, ok := s.roles[id]; ok {
		return role.Name
	}
	return ""
}

// roleIDByName is the reverse, for rendering a member's roles array. Caller
// holds the lock.
func (s *Server) roleIDByName(name string) string {
	for _, role := range s.roles {
		if role.Name == name {
			return role.ID
		}
	}
	return ""
}

// unknownRoleIDs returns the ids that name no role, so an invitation cannot
// carry a grant that resolves to nothing. Caller holds the lock.
func (s *Server) unknownRoleIDs(ids []string) []string {
	var unknown []string
	for _, id := range ids {
		if _, ok := s.roles[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	return unknown
}
