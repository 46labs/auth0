package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/46labs/auth0/pkg/config"
)

// handleConnection serves a single connection by id, plus its clients
// subresource. Anything else under /connections/{id}/ must 404 rather than
// fall through: truncating the path at the slash would dispatch
// DELETE .../connections/{id}/clients to deleteConnection and destroy the
// connection, which is the same class of bug the organization router had.
func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	segments := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/connections/"), "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		if r.Method == http.MethodOptions {
			return
		}
		writeAuth0Error(w, http.StatusNotFound, "route not implemented by the auth0 mock: "+r.URL.Path)
		return
	}
	connID := segments[0]

	if len(segments) == 2 && segments[1] == "clients" {
		s.handleConnectionClients(w, r, connID)
		return
	}
	if len(segments) != 1 {
		if r.Method == http.MethodOptions {
			return
		}
		writeAuth0Error(w, http.StatusNotFound, "route not implemented by the auth0 mock: "+r.URL.Path)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getConnection(w, connID)
	case http.MethodPatch:
		s.updateConnection(w, r, connID)
	case http.MethodDelete:
		s.deleteConnection(w, connID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) getConnection(w http.ResponseWriter, connID string) {
	s.mu.RLock()
	conn, ok := s.connections[connID]
	var out *config.Connection
	if ok {
		out = conn.Clone()
	}
	s.mu.RUnlock()

	if !ok {
		writeAuth0Error(w, http.StatusNotFound, "connection not found")
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

// updateConnection patches a connection. Auth0 replaces `options` wholesale
// rather than merging it, so a caller correcting one OIDC field has to send the
// whole block; merging here would hide that from consumers until production.
// name and strategy are immutable in Auth0 and are ignored.
func (s *Server) updateConnection(w http.ResponseWriter, r *http.Request, connID string) {
	var patch struct {
		DisplayName    *string                `json:"display_name"`
		EnabledClients *[]string              `json:"enabled_clients"`
		Options        map[string]interface{} `json:"options"`
		Metadata       map[string]string      `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}

	s.mu.Lock()
	conn, ok := s.connections[connID]
	if !ok {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusNotFound, "connection not found")
		return
	}
	if patch.DisplayName != nil {
		conn.DisplayName = *patch.DisplayName
	}
	if patch.EnabledClients != nil {
		conn.EnabledClients = append([]string(nil), (*patch.EnabledClients)...)
	}
	if patch.Options != nil {
		conn.Options = patch.Options
	}
	out := conn.Clone()
	s.mu.Unlock()

	_ = json.NewEncoder(w).Encode(out)
}

// deleteConnection removes a connection and every organization pairing that
// referenced it. Leaving the pairings behind would let an organization report
// an enabled connection that no longer exists, which reads as a working login
// path right up until someone tries it.
func (s *Server) deleteConnection(w http.ResponseWriter, connID string) {
	s.mu.Lock()
	if _, ok := s.connections[connID]; !ok {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusNotFound, "connection not found")
		return
	}
	delete(s.connections, connID)
	for orgID, pairings := range s.orgConnections {
		kept := pairings[:0]
		for _, p := range pairings {
			if p.ConnectionID != connID {
				kept = append(kept, p)
			}
		}
		s.orgConnections[orgID] = kept
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// connectionClient is one entry of the /connections/{id}/clients payload. Auth0
// sends and receives a bare JSON array of these, not an object wrapper.
type connectionClient struct {
	ClientID string `json:"client_id"`
	Status   bool   `json:"status"`
}

// handleConnectionClients serves the enabled-clients subresource. A connection
// must be enabled on both its organization and the application that calls
// /authorize; enabling only the organization fails the login, so this is not
// optional for a consumer provisioning connections at runtime.
func (s *Server) handleConnectionClients(w http.ResponseWriter, r *http.Request, connID string) {
	switch r.Method {
	case http.MethodGet:
		s.listConnectionClients(w, connID)
	case http.MethodPatch:
		s.updateConnectionClients(w, r, connID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listConnectionClients(w http.ResponseWriter, connID string) {
	s.mu.RLock()
	conn, ok := s.connections[connID]
	var clients []connectionClient
	if ok {
		clients = make([]connectionClient, 0, len(conn.EnabledClients))
		for _, id := range conn.EnabledClients {
			clients = append(clients, connectionClient{ClientID: id, Status: true})
		}
	}
	s.mu.RUnlock()

	if !ok {
		writeAuth0Error(w, http.StatusNotFound, "connection not found")
		return
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ClientID < clients[j].ClientID })
	_ = json.NewEncoder(w).Encode(map[string]any{"clients": clients})
}

// updateConnectionClients enables or disables named clients. It is a delta, not
// a replacement: Auth0 takes status false to mean "remove this one", and
// omitting a client leaves it alone. Treating the array as the whole set would
// silently drop clients a caller did not mention.
func (s *Server) updateConnectionClients(w http.ResponseWriter, r *http.Request, connID string) {
	var patch []connectionClient
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body: expected an array of {client_id, status}")
		return
	}

	s.mu.Lock()
	conn, ok := s.connections[connID]
	if !ok {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusNotFound, "connection not found")
		return
	}
	for _, c := range patch {
		if c.ClientID == "" {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusBadRequest, "client_id is required")
			return
		}
		if _, exists := s.clients[c.ClientID]; !exists {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusBadRequest, "unknown client "+c.ClientID)
			return
		}
	}
	for _, c := range patch {
		conn.EnabledClients = setClientEnabled(conn.EnabledClients, c.ClientID, c.Status)
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func setClientEnabled(current []string, clientID string, enabled bool) []string {
	out := make([]string, 0, len(current)+1)
	for _, id := range current {
		if id != clientID {
			out = append(out, id)
		}
	}
	if enabled {
		out = append(out, clientID)
	}
	sort.Strings(out)
	return out
}
