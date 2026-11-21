package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/46labs/auth0/pkg/config"
)

// Tenant roles held by users: /api/v2/users/{id}/roles and
// /api/v2/roles/{id}/users. Organization roles are separate (members).

// seedUserRoles resolves each configured user's role names to role ids. An
// unknown name fails startup rather than granting nothing silently.
func seedUserRoles(users []config.User, roles map[string]*config.Role) (map[string][]string, error) {
	byName := make(map[string]string, len(roles))
	for id, r := range roles {
		byName[r.Name] = id
	}
	out := make(map[string][]string)
	for _, u := range users {
		for _, name := range u.Roles {
			id, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("user %s: unknown role %q", u.ID, name)
			}
			if !slices.Contains(out[u.ID], id) {
				out[u.ID] = append(out[u.ID], id)
			}
		}
	}
	return out, nil
}

// tenantRolesLocked returns userID's roles sorted by name. Caller holds the lock.
func (s *Server) tenantRolesLocked(userID string) []config.Role {
	out := make([]config.Role, 0, len(s.userRoles[userID]))
	for _, id := range s.userRoles[userID] {
		if r, ok := s.roles[id]; ok {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// tenantRoleNames is event.authorization.roles: the names of the user's
// tenant roles.
func (s *Server) tenantRoleNames(userID string) []any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := []any{}
	for _, r := range s.tenantRolesLocked(userID) {
		names = append(names, r.Name)
	}
	return names
}

// removeUserRolesLocked drops a deleted user's assignments. Caller holds the
// write lock.
func (s *Server) removeUserRolesLocked(userID string) {
	delete(s.userRoles, userID)
}

// unassignRoleLocked drops a deleted role from every user. Caller holds the
// write lock.
func (s *Server) unassignRoleLocked(roleID string) {
	for userID, ids := range s.userRoles {
		s.userRoles[userID] = slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id == roleID })
	}
}

// handleUserRoles serves /api/v2/users/{id}/roles.
func (s *Server) handleUserRoles(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")
	userID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/users/"), "/roles")

	switch r.Method {
	case http.MethodGet:
		s.listUserRoles(w, r, userID)
	case http.MethodPost, http.MethodDelete:
		s.changeUserRoles(w, r, userID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listUserRoles(w http.ResponseWriter, r *http.Request, userID string) {
	if msg := invalidListQuery(r, "page", "per_page", "include_totals"); msg != "" {
		writeAuth0Error(w, http.StatusBadRequest, msg)
		return
	}
	s.mu.RLock()
	_, exists := s.users[userID]
	all := s.tenantRolesLocked(userID)
	s.mu.RUnlock()

	if !exists {
		writeAuth0Error(w, http.StatusNotFound, "user not found")
		return
	}
	lo, hi, window := paginate(r, len(all))
	writeAuth0List(w, r, "roles", all[lo:hi], window)
}

// writeAuth0List is writeList with the envelope Auth0's OpenAPI document
// gives these endpoints: start, limit, and total, no length.
func writeAuth0List(w http.ResponseWriter, r *http.Request, key string, items any, window listWindow) {
	if r.URL.Query().Get("include_totals") != "true" {
		_ = json.NewEncoder(w).Encode(items)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{key: items, "start": window.Start, "limit": window.Limit, "total": window.Total})
}

// invalidListQuery checks the paging parameters against the OpenAPI
// document's bounds (page >= 0, per_page and take 1 to 100, include_totals a
// boolean), refusing what Auth0 refuses where paginate would clamp. It
// returns the problem, or "" when the query is valid.
func invalidListQuery(r *http.Request, allowed ...string) string {
	q := r.URL.Query()
	bounds := map[string][2]int{"page": {0, math.MaxInt}, "per_page": {1, 100}, "take": {1, 100}}
	for _, name := range allowed {
		if !q.Has(name) {
			continue
		}
		v := q.Get(name)
		if name == "include_totals" {
			if v != "true" && v != "false" {
				return "Invalid request query string: include_totals must be a boolean"
			}
			continue
		}
		b, ok := bounds[name]
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < b[0] || n > b[1] {
			return fmt.Sprintf("Invalid request query string: %s is out of range", name)
		}
	}
	return ""
}

// decodeStrict decodes a request body, refusing fields the schema does not
// have (additionalProperties: false).
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the body")
	}
	return nil
}

// changeUserRoles assigns (POST) or removes (DELETE) role ids. Both answer
// 204 (TestUserManager_Roles.yaml).
func (s *Server) changeUserRoles(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Roles []string `json:"roles"`
	}
	if err := decodeStrict(r, &req); err != nil || len(req.Roles) == 0 {
		writeAuth0Error(w, http.StatusBadRequest, "Payload validation error: roles must name at least one role")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[userID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "user not found")
		return
	}
	if unknown := s.unknownRoleIDs(req.Roles); len(unknown) > 0 {
		writeAuth0Error(w, http.StatusBadRequest, "unknown role ids: "+strings.Join(unknown, ", "))
		return
	}
	ids := slices.Clone(s.userRoles[userID])
	for _, id := range req.Roles {
		if r.Method == http.MethodDelete {
			ids = slices.DeleteFunc(ids, func(have string) bool { return have == id })
		} else if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	s.userRoles[userID] = ids
	w.WriteHeader(http.StatusNoContent)
}

// roleUser is a role member as Auth0 lists one (TestRoleManager_Users.yaml).
type roleUser struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email,omitempty"`
	Picture string `json:"picture,omitempty"`
	Name    string `json:"name,omitempty"`
}

// handleRoleUsers serves /api/v2/roles/{id}/users.
func (s *Server) handleRoleUsers(w http.ResponseWriter, r *http.Request, roleID string) {
	switch r.Method {
	case http.MethodGet:
		s.listRoleUsers(w, r, roleID)
	case http.MethodPost:
		s.assignRoleUsers(w, r, roleID)
	case http.MethodOptions:
		return
	default:
		// Auth0 has no other method here, and answers 404.
		writeAuth0Error(w, http.StatusNotFound, "route not implemented by the auth0 mock: "+r.URL.Path)
	}
}

// listRoleUsers pages by page/per_page, or by checkpoint when the caller
// sends take or from (TestRoleManager_UsersCheckpointPagination.yaml): the
// checkpoint page carries next, and no start, limit, or total.
func (s *Server) listRoleUsers(w http.ResponseWriter, r *http.Request, roleID string) {
	if msg := invalidListQuery(r, "page", "per_page", "include_totals", "from", "take"); msg != "" {
		writeAuth0Error(w, http.StatusBadRequest, msg)
		return
	}
	s.mu.RLock()
	_, exists := s.roles[roleID]
	var all []roleUser
	for userID, ids := range s.userRoles {
		if !slices.Contains(ids, roleID) {
			continue
		}
		ru := roleUser{UserID: userID}
		if u, ok := s.users[userID]; ok {
			ru.Email, ru.Picture, ru.Name = u.Email, u.Picture, u.Name
		}
		all = append(all, ru)
	}
	s.mu.RUnlock()

	if !exists {
		writeAuth0Error(w, http.StatusNotFound, "role not found")
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].UserID < all[j].UserID })
	if all == nil {
		all = []roleUser{}
	}

	q := r.URL.Query()
	if q.Has("take") || q.Has("from") {
		// The cursor is opaque, as Auth0's is: the user_id to resume after,
		// base64-encoded.
		lo := 0
		if from := q.Get("from"); from != "" {
			after, err := base64.StdEncoding.DecodeString(from)
			if err != nil {
				writeAuth0Error(w, http.StatusBadRequest, "Invalid request query string: from is not a valid checkpoint")
				return
			}
			lo = sort.Search(len(all), func(i int) bool { return all[i].UserID > string(after) })
		}
		hi := min(lo+checkpointTake(r), len(all))
		page := map[string]any{"users": all[lo:hi]}
		if hi < len(all) {
			page["next"] = base64.StdEncoding.EncodeToString([]byte(all[hi-1].UserID))
		}
		_ = json.NewEncoder(w).Encode(page)
		return
	}

	lo, hi, window := paginate(r, len(all))
	writeAuth0List(w, r, "users", all[lo:hi], window)
}

// assignRoleUsers answers 200 with {} (TestRoleManager_Users.yaml).
func (s *Server) assignRoleUsers(w http.ResponseWriter, r *http.Request, roleID string) {
	// users is required but may be empty: the schema sets no minItems.
	var req struct {
		Users *[]string `json:"users"`
	}
	if err := decodeStrict(r, &req); err != nil || req.Users == nil {
		writeAuth0Error(w, http.StatusBadRequest, "Payload validation error: users is required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.roles[roleID]; !ok {
		writeAuth0Error(w, http.StatusNotFound, "role not found")
		return
	}
	for _, id := range *req.Users {
		if _, ok := s.users[id]; !ok {
			writeAuth0Error(w, http.StatusNotFound, "user not found: "+id)
			return
		}
	}
	for _, id := range *req.Users {
		if !slices.Contains(s.userRoles[id], roleID) {
			s.userRoles[id] = append(slices.Clone(s.userRoles[id]), roleID)
		}
	}
	_ = json.NewEncoder(w).Encode(struct{}{})
}
