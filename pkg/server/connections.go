package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/contact"

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
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}
	// Anything config.Connection cannot hold is refused rather than accepted
	// and dropped. Silently ignoring a field answers 200 while the next read
	// loses the write, which reads as a converged provisioning run that did
	// nothing. name and strategy are immutable in Auth0 and ignored, matching it.
	for k := range raw {
		switch k {
		case "display_name", "enabled_clients", "options", "name", "strategy", "id":
		default:
			writeAuth0Error(w, http.StatusBadRequest, "connection field not implemented by the auth0 mock: "+k)
			return
		}
	}
	var patch struct {
		DisplayName    *string                `json:"display_name"`
		EnabledClients *[]string              `json:"enabled_clients"`
		Options        map[string]interface{} `json:"options"`
	}
	body, _ := json.Marshal(raw)
	if err := json.Unmarshal(body, &patch); err != nil {
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

// deleteConnection removes a connection, its users, and every organization
// pairing that referenced it.
//
// The SDK documents Delete as removing the connection *and all its users*, so
// dropping only the connection would leave those users readable and still able
// to authenticate. Pairings go too: one left pointing at a deleted connection
// reads as a working login path right up until someone tries it.
//
// Auth0 answers 202 with a deleted_at body here, not 204
// (TestConnectionManager_Delete.yaml).
func (s *Server) deleteConnection(w http.ResponseWriter, connID string) {
	s.mu.Lock()
	conn, ok := s.connections[connID]
	if !ok {
		s.mu.Unlock()
		// Auth0 records a repeated delete of the same id as 204 with an empty
		// body, not 404 (TestConnectionManager_Delete.yaml). Retried cleanup
		// must not look like a different outcome locally.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	connName := conn.Name
	delete(s.connections, connID)

	orphaned := map[string]bool{}
	for id, u := range s.users {
		for _, ident := range u.Identities {
			if ident.Connection == connName {
				orphaned[id] = true
				break
			}
		}
	}
	for id := range orphaned {
		delete(s.users, id)
	}
	// Membership is per-organization state keyed by user, so it has to follow
	// the user out or the org keeps listing a member who no longer exists.
	for orgID, ms := range s.members {
		kept := ms[:0]
		for _, m := range ms {
			if !orphaned[m.UserID] {
				kept = append(kept, m)
			}
		}
		s.members[orgID] = kept
	}
	for orgID, pairings := range s.orgConnections {
		kept := pairings[:0]
		for _, p := range pairings {
			if p.ConnectionID != connID {
				kept = append(kept, p)
			}
		}
		s.orgConnections[orgID] = kept
	}
	// Pending invitations that named this connection have to go too. An
	// invitation URL can omit `connection`, and redemption does not revalidate
	// that the stored one still exists, so a ticket issued before the delete
	// would still mint a user and a membership against a connection nobody can
	// authenticate through.
	for orgID, invites := range s.invitations {
		// An invitation with no connection_id relies on the organization still
		// having some connection it could be redeemed through. Once the last
		// non-passwordless one is gone, creating that invitation would now be
		// rejected, so an outstanding ticket must not stay redeemable either.
		unbindable := !s.orgHasInvitableConnectionLocked(orgID)
		kept := invites[:0]
		for _, inv := range invites {
			if inv.ConnectionID == connID {
				continue
			}
			if inv.ConnectionID == "" && unbindable {
				continue
			}
			kept = append(kept, inv)
		}
		s.invitations[orgID] = kept
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"deleted_at": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	})
}

// orgHasInvitableConnectionLocked reports whether the organization still
// enables a connection an invitation could be redeemed through. Auth0 refuses
// invitations on passwordless connections, so those do not count.
func (s *Server) orgHasInvitableConnectionLocked(orgID string) bool {
	for _, oc := range s.orgConnections[orgID] {
		c, ok := s.connections[oc.ConnectionID]
		if ok && !c.IsPasswordless() {
			return true
		}
	}
	return false
}

// connectionClient is one entry of the PATCH /connections/{id}/clients request,
// which Auth0 takes as a bare JSON array rather than an object wrapper.
type connectionClient struct {
	ClientID string `json:"client_id"`
	// Pointer, because the SDK omits status when the caller leaves it nil.
	// Decoding into a plain bool would turn that omission into false and
	// silently disable the client while answering 204.
	Status *bool `json:"status"`
}

// connectionClientView is the GET shape, which carries client_id only. Echoing
// status back would make the SDK's GetStatus() report true locally and false
// against Auth0, where the field is absent
// (TestConnectionManager_EnabledClients.yaml).
type connectionClientView struct {
	ClientID string `json:"client_id"`
}

// handleConnectionClients serves the enabled-clients subresource. A connection
// must be enabled on both its organization and the application that calls
// /authorize; enabling only the organization fails the login, so this is not
// optional for a consumer provisioning connections at runtime.
func (s *Server) handleConnectionClients(w http.ResponseWriter, r *http.Request, connID string) {
	switch r.Method {
	case http.MethodGet:
		s.listConnectionClients(w, r, connID)
	case http.MethodPatch:
		s.updateConnectionClients(w, r, connID)
	case http.MethodOptions:
		return
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listConnectionClients(w http.ResponseWriter, r *http.Request, connID string) {
	s.mu.RLock()
	conn, ok := s.connections[connID]
	var clients []connectionClientView
	if ok {
		clients = make([]connectionClientView, 0, len(conn.EnabledClients))
		for _, id := range conn.EnabledClients {
			clients = append(clients, connectionClientView{ClientID: id})
		}
	}
	s.mu.RUnlock()

	if !ok {
		writeAuth0Error(w, http.StatusNotFound, "connection not found")
		return
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ClientID < clients[j].ClientID })

	// Windowed like every other list endpoint. Returning the whole slice for
	// any page lets an SDK pager loop forever on the same content.
	lo, hi, _ := paginate(r, len(clients))
	_ = json.NewEncoder(w).Encode(map[string]any{"clients": clients[lo:hi]})
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
		if c.Status == nil {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusBadRequest, "status is required for "+c.ClientID)
			return
		}
		if _, exists := s.clients[c.ClientID]; !exists {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusBadRequest, "unknown client "+c.ClientID)
			return
		}
	}
	all := make([]string, 0, len(s.clients))
	for id := range s.clients {
		all = append(all, id)
	}
	for _, c := range patch {
		conn.EnabledClients = setClientEnabled(conn.EnabledClients, all, c.ClientID, *c.Status)
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// connectionAllowsClientLocked reports whether clientID may authenticate
// against the named connection.
//
// Fail-closed on everything ambiguous. The states are deliberately distinct:
//
//	nil EnabledClients   legacy fixture that never declared a list, unrestricted
//	empty EnabledClients every client was disabled, so nothing may authorize
//	unknown connName     a deleted or typoed connection, refused
//
// Treating the empty set as unrestricted would let the last disable read back
// as "no clients" while that client kept signing in, which is the whole failure
// this endpoint exists to make visible.
func (s *Server) connectionAllowsClientLocked(connName, clientID string) bool {
	if connName == "" {
		return true // caller resolved nothing to check against
	}
	for _, c := range s.connections {
		if c.Name != connName {
			continue
		}
		if c.EnabledClients == nil {
			return true
		}
		for _, id := range c.EnabledClients {
			if id == "*" || id == clientID {
				return true
			}
		}
		return false
	}
	// Nonempty name that resolves to nothing: deleted, or a typo. Allowing it
	// would mean deletion never actually disables explicit login.
	return false
}

// inferConnectionNameLocked resolves the connection an /authorize request will
// actually use when the caller omitted one, mirroring how the login path picks
// email or sms from the identifier. Without this the client gate only applies
// to callers who explicitly pin a connection.
func (s *Server) inferConnectionNameLocked(identifier string) string {
	want := config.StrategySMS
	if contact.IsEmail(identifier) {
		want = config.StrategyEmail
	}
	for _, c := range s.connections {
		if c.Strategy == want {
			return c.Name
		}
	}
	return ""
}

// setClientEnabled applies one client's status.
//
// allClients is used to expand a "*" wildcard when a specific client is being
// disabled: leaving the wildcard in place would drop the client from the read
// while authorization still succeeded through "*".
func setClientEnabled(current, allClients []string, clientID string, enabled bool) []string {
	expanded := current
	if !enabled && containsString(current, "*") {
		expanded = append([]string(nil), allClients...)
	}

	out := make([]string, 0, len(expanded)+1)
	for _, id := range expanded {
		if id != clientID {
			out = append(out, id)
		}
	}
	if enabled && !containsString(out, "*") {
		out = append(out, clientID)
	}
	sort.Strings(out)
	return out
}

func containsString(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}
