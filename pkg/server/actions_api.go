package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

// The Actions Management API.
//
// The mock does not execute Action JavaScript — it simulates the resulting
// claims from static config — but consumers still reconcile Actions through
// this API, and without it that whole path is unreachable locally. PEE's
// reconciler reads the offered triggers first and treats a 404 there as "this
// upstream has no Actions API", so every later call, including the token
// exchange profile it creates, went untested until a real tenant refused one.
//
// Deploying is therefore recorded rather than performed: an Action created here
// is inert, and only its bookkeeping is observable.

// actionsTriggers is the trigger inventory this mock claims to offer. The
// versions matter: a consumer pins the contract version its source is written
// against and refuses to deploy against a tenant that does not list it.
var actionsTriggers = []map[string]any{
	{"id": "post-login", "version": "v3", "status": "CURRENT"},
	{"id": "credentials-exchange", "version": "v2", "status": "CURRENT"},
	{"id": "custom-token-exchange", "version": "v1", "status": "CURRENT"},
	{"id": "pre-user-registration", "version": "v2", "status": "CURRENT"},
	{"id": "post-user-registration", "version": "v2", "status": "CURRENT"},
}

// routeActionsPath dispatches everything under /api/v2/actions/. Auth0 nests a
// second segment, so the real paths are /api/v2/actions/actions and
// /api/v2/actions/triggers.
func (s *Server) routeActionsPath(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		return
	}

	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/actions/"), "/")
	segments := strings.Split(rest, "/")

	switch {
	case len(segments) == 1 && segments[0] == "triggers":
		s.handleActionTriggers(w, r)
	case len(segments) == 3 && segments[0] == "triggers" && segments[2] == "bindings":
		s.handleTriggerBindings(w, r, segments[1])
	case len(segments) == 1 && segments[0] == "actions":
		s.handleActionsCollection(w, r)
	case len(segments) == 2 && segments[0] == "actions":
		s.handleAction(w, r, segments[1])
	case len(segments) == 3 && segments[0] == "actions" && segments[2] == "deploy":
		s.handleActionDeploy(w, r, segments[1])
	default:
		writeAuth0Error(w, http.StatusNotFound, "route not implemented by the auth0 mock: "+r.URL.Path)
	}
}

func (s *Server) handleActionTriggers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"triggers": actionsTriggers})
}

func (s *Server) handleActionsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listActions(w, r)
	case http.MethodPost:
		s.createAction(w, r)
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// listActions serves GET /api/v2/actions/actions. Auth0 filters by name
// server-side and a consumer that asks for one name relies on that rather than
// scanning, so an unfiltered answer would let it adopt somebody else's Action.
func (s *Server) listActions(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("actionName")

	s.mu.RLock()
	out := make([]map[string]any, 0, len(s.actions))
	for _, a := range s.actions {
		if name != "" && a["name"] != name {
			continue
		}
		out = append(out, cloneJSONMap(a))
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	_ = json.NewEncoder(w).Encode(map[string]any{
		"actions": out, "total": len(out), "page": 0, "per_page": len(out),
	})
}

func (s *Server) createAction(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, "invalid body")
		return
	}
	name, _ := body["name"].(string)
	if name == "" {
		writeAuth0Error(w, http.StatusBadRequest, "name is required")
		return
	}

	s.mu.Lock()
	for _, a := range s.actions {
		if a["name"] == name {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusConflict, "an action with this name already exists")
			return
		}
	}
	body["id"] = "act_" + s.generateID()
	// Auth0 builds asynchronously and a consumer polls Read until the status
	// leaves "pending". Nothing is compiled here, so it is built on arrival —
	// but the field has to be present, or that poll spins until it gives up
	// with "action did not finish building".
	body["status"] = "built"
	// Built is not deployed; a consumer deploys as a separate call and may
	// check this before doing so.
	body["all_changes_deployed"] = false
	s.actions[body["id"].(string)] = body
	out := cloneJSONMap(body)
	s.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		a, ok := s.actions[id]
		var out map[string]any
		if ok {
			out = cloneJSONMap(a)
		}
		s.mu.RUnlock()
		if !ok {
			writeAuth0Error(w, http.StatusNotFound, "action not found")
			return
		}
		_ = json.NewEncoder(w).Encode(out)

	case http.MethodPatch:
		var patch map[string]any
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeAuth0Error(w, http.StatusBadRequest, "invalid body")
			return
		}
		s.mu.Lock()
		a, ok := s.actions[id]
		if !ok {
			s.mu.Unlock()
			writeAuth0Error(w, http.StatusNotFound, "action not found")
			return
		}
		for k, v := range patch {
			a[k] = v
		}
		// Editing an Action leaves the deployed version behind until the
		// consumer deploys again, which is what makes the deploy call load
		// bearing rather than decorative. The rebuild is instantaneous here for
		// the same reason creation is.
		a["status"] = "built"
		a["all_changes_deployed"] = false
		out := cloneJSONMap(a)
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(out)

	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleActionDeploy(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.mu.Lock()
	a, ok := s.actions[id]
	if !ok {
		s.mu.Unlock()
		writeAuth0Error(w, http.StatusNotFound, "action not found")
		return
	}
	a["all_changes_deployed"] = true
	version := map[string]any{
		"id":       "ver_" + s.generateID(),
		"code":     a["code"],
		"deployed": true,
		"status":   "built",
		"number":   1,
	}
	a["deployed_version"] = version
	out := cloneJSONMap(version)
	s.mu.Unlock()

	_ = json.NewEncoder(w).Encode(out)
}

// handleTriggerBindings serves the bindings for one trigger. Auth0 replaces the
// whole list on PATCH, so a consumer that appends has to send everything it
// wants to keep — modelling anything else would hide that from it.
func (s *Server) handleTriggerBindings(w http.ResponseWriter, r *http.Request, triggerID string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		bindings := make([]map[string]any, 0, len(s.actionBindings[triggerID]))
		for _, b := range s.actionBindings[triggerID] {
			bindings = append(bindings, cloneJSONMap(b))
		}
		s.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bindings": bindings, "total": len(bindings), "page": 0, "per_page": len(bindings),
		})

	case http.MethodPatch:
		var body struct {
			Bindings []map[string]any `json:"bindings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeAuth0Error(w, http.StatusBadRequest, "invalid body")
			return
		}

		s.mu.Lock()
		stored := make([]map[string]any, 0, len(body.Bindings))
		for _, b := range body.Bindings {
			binding := cloneJSONMap(b)
			binding["id"] = "bnd_" + s.generateID()
			binding["trigger_id"] = triggerID
			// Auth0 answers with the bound Action itself, not the ref the
			// caller sent, and a consumer reads the name from it to tell its
			// own binding from somebody else's.
			if ref, ok := b["ref"].(map[string]any); ok {
				if name, _ := ref["value"].(string); name != "" {
					for _, a := range s.actions {
						if a["name"] == name {
							binding["action"] = cloneJSONMap(a)
						}
					}
				}
			}
			stored = append(stored, binding)
		}
		s.actionBindings[triggerID] = stored
		out := make([]map[string]any, 0, len(stored))
		for _, b := range stored {
			out = append(out, cloneJSONMap(b))
		}
		s.mu.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]any{"bindings": out})

	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleTokenExchangeProfiles serves /api/v2/token-exchange-profiles.
//
// Checkpoint-paginated, unlike the offset-paginated listings elsewhere: this
// endpoint rejects include_totals outright, and answering an envelope with
// start/limit/total would hide a consumer sending the wrong one.
func (s *Server) handleTokenExchangeProfiles(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodOptions:
		return

	case http.MethodGet:
		if r.URL.Query().Has("include_totals") {
			writeAuth0Error(w, http.StatusBadRequest,
				"Query validation error: 'Additional properties not allowed: include_totals'.")
			return
		}
		s.mu.RLock()
		out := make([]map[string]any, 0, len(s.tokenExchangeProfiles))
		for _, p := range s.tokenExchangeProfiles {
			out = append(out, cloneJSONMap(p))
		}
		s.mu.RUnlock()
		sort.Slice(out, func(i, j int) bool {
			return out[i]["id"].(string) < out[j]["id"].(string)
		})
		_ = json.NewEncoder(w).Encode(map[string]any{"token_exchange_profiles": out})

	case http.MethodPost:
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeAuth0Error(w, http.StatusBadRequest, "invalid body")
			return
		}
		subjectType, _ := body["subject_token_type"].(string)
		actionID, _ := body["action_id"].(string)
		if subjectType == "" || actionID == "" {
			writeAuth0Error(w, http.StatusBadRequest, "subject_token_type and action_id are required")
			return
		}

		s.mu.Lock()
		for _, p := range s.tokenExchangeProfiles {
			if p["subject_token_type"] == subjectType {
				s.mu.Unlock()
				writeAuth0Error(w, http.StatusConflict,
					"a profile for this subject_token_type already exists")
				return
			}
		}
		body["id"] = "tep_" + s.generateID()
		s.tokenExchangeProfiles[body["id"].(string)] = body
		out := cloneJSONMap(body)
		s.mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(out)

	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// cloneJSONMap copies a decoded JSON object one level deep, so a handler
// serializing outside the lock cannot race a writer mutating the stored map.
func cloneJSONMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if nested, ok := v.(map[string]any); ok {
			out[k] = cloneJSONMap(nested)
			continue
		}
		out[k] = v
	}
	return out
}
