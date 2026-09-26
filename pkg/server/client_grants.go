package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

// clientGrant authorizes one client for one API. A machine credential that
// authenticates without a grant for the audience it asks for is issued a token
// real Auth0 refuses, so consumers that provision credentials need this to
// exist here too — otherwise the mock is the only place their flow succeeds.
type clientGrant struct {
	ID       string   `json:"id"`
	ClientID string   `json:"client_id"`
	Audience string   `json:"audience"`
	Scope    []string `json:"scope"`
}

// handleClientGrants serves /api/v2/client-grants.
func (s *Server) handleClientGrants(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.listClientGrants(w, r)
	case http.MethodPost:
		s.createClientGrant(w, r)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listClientGrants(w http.ResponseWriter, r *http.Request) {
	wantClient := r.URL.Query().Get("client_id")
	wantAudience := r.URL.Query().Get("audience")

	s.mu.RLock()
	all := make([]clientGrant, 0, len(s.clientGrants))
	for _, g := range s.clientGrants {
		if wantClient != "" && g.ClientID != wantClient {
			continue
		}
		if wantAudience != "" && g.Audience != wantAudience {
			continue
		}
		all = append(all, *g)
	}
	s.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	lo, hi, window := paginate(r, len(all))
	page := all[lo:hi]
	writeList(w, r, "client_grants", page, window, len(page))
}

func (s *Server) createClientGrant(w http.ResponseWriter, r *http.Request) {
	var grant clientGrant
	if err := json.NewDecoder(r.Body).Decode(&grant); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}
	if grant.ClientID == "" || grant.Audience == "" {
		writeAuth0Error(w, http.StatusBadRequest, "client_id and audience are required")
		return
	}

	s.mu.Lock()
	if _, ok := s.clients[grant.ClientID]; !ok {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusBadRequest, "client not found: "+grant.ClientID)
		return
	}
	// Auth0 refuses a duplicate pairing rather than creating a second grant, and
	// a consumer reconciling grants relies on that to stay idempotent.
	for _, g := range s.clientGrants {
		if g.ClientID == grant.ClientID && g.Audience == grant.Audience {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusConflict, "grant already exists for this client and audience")
			return
		}
	}
	if grant.ID == "" {
		grant.ID = "cgr_" + s.generateID()
	}
	if grant.Scope == nil {
		grant.Scope = []string{}
	}
	stored := grant
	s.clientGrants[grant.ID] = &stored
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(grant)
}

// rotateClientSecret issues a new secret and discards the old one, which is the
// only way to recover a credential whose secret was lost: Auth0 discloses it
// once, at creation.
func (s *Server) rotateClientSecret(w http.ResponseWriter, clientID string) {
	s.mu.Lock()
	client, ok := s.clients[clientID]
	if !ok {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusNotFound, "client not found")
		return
	}
	client.ClientSecret = "rotated_" + s.generateID()
	out := *client
	s.mu.Unlock()

	_ = json.NewEncoder(w).Encode(out)
}

// deleteClientGrantsFor removes the grants belonging to a deleted client. A
// grant left pointing at a client that no longer exists would keep answering
// list queries and read as a working authorization.
func (s *Server) deleteClientGrantsFor(clientID string) {
	for id, g := range s.clientGrants {
		if g.ClientID == clientID {
			delete(s.clientGrants, id)
		}
	}
}

// clientSubPath returns the subresource under /api/v2/clients/{id}/, or "".
func clientSubPath(path string) (clientID, sub string) {
	rest := strings.Trim(strings.TrimPrefix(path, "/api/v2/clients/"), "/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return rest, ""
}
