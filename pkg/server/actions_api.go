package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleActionsAPI routes everything under /api/v2/actions/.
func (s *Server) handleActionsAPI(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/actions/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case parts[0] == "triggers" && len(parts) == 1:
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"triggers": supportedTriggers()})
	case parts[0] == "triggers" && len(parts) == 3 && parts[2] == "bindings":
		s.handleTriggerBindings(w, r, parts[1])
	case parts[0] == "actions" && len(parts) == 1:
		switch r.Method {
		case http.MethodGet:
			s.listActions(w, r)
		case http.MethodPost:
			s.createAction(w, r)
		default:
			methodNotAllowed(w)
		}
	case parts[0] == "actions" && len(parts) == 2:
		s.handleAction(w, r, parts[1])
	case parts[0] == "actions" && len(parts) == 3 && parts[2] == "deploy":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		v, err := s.actions.deploy(parts[1], s.generateID())
		if writeActionErr(w, err) {
			return
		}
		writeJSON(w, http.StatusOK, v)
	case parts[0] == "actions" && len(parts) == 3 && parts[2] == "versions":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		vs, err := s.actions.versions(parts[1])
		if writeActionErr(w, err) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": vs, "total": len(vs), "page": 0, "per_page": len(vs)})
	default:
		http.Error(w, `{"statusCode":404,"error":"Not Found"}`, http.StatusNotFound)
	}
}

func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, `{"statusCode":405,"error":"Method Not Allowed"}`, http.StatusMethodNotAllowed)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeActionErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, errActionNotFound):
		http.Error(w, `{"statusCode":404,"error":"Not Found","message":"`+err.Error()+`"}`, http.StatusNotFound)
	case errors.Is(err, errActionNameTaken), errors.Is(err, errActionBound):
		http.Error(w, `{"statusCode":409,"error":"Conflict","message":"`+err.Error()+`"}`, http.StatusConflict)
	default:
		http.Error(w, `{"statusCode":400,"error":"Bad Request","message":"`+err.Error()+`"}`, http.StatusBadRequest)
	}
	return true
}

// actionBody is the wire shape of POST and PATCH /api/v2/actions/actions.
type actionBody struct {
	Name              *string             `json:"name"`
	SupportedTriggers *[]ActionTriggerRef `json:"supported_triggers"`
	Code              *string             `json:"code"`
	Dependencies      *[]ActionDependency `json:"dependencies"`
	Runtime           *string             `json:"runtime"`
	Secrets           *[]struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"secrets"`
}

func (b actionBody) secrets() []ActionSecret {
	if b.Secrets == nil {
		return nil
	}
	out := make([]ActionSecret, 0, len(*b.Secrets))
	for _, s := range *b.Secrets {
		out = append(out, ActionSecret{Name: s.Name, value: s.Value})
	}
	return out
}

func (s *Server) listActions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var deployed *bool
	if v := q.Get("deployed"); v != "" {
		b, _ := strconv.ParseBool(v)
		deployed = &b
	}
	list := s.actions.list(q.Get("actionName"), q.Get("triggerId"), deployed)
	writeJSON(w, http.StatusOK, map[string]any{"actions": list, "total": len(list), "page": 0, "per_page": len(list)})
}

func (s *Server) createAction(w http.ResponseWriter, r *http.Request) {
	var b actionBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, `{"statusCode":400,"error":"Bad Request","message":"invalid body"}`, http.StatusBadRequest)
		return
	}
	in := Action{Secrets: b.secrets()}
	if b.Name != nil {
		in.Name = *b.Name
	}
	if b.Code != nil {
		in.Code = *b.Code
	}
	if b.Runtime != nil {
		in.Runtime = *b.Runtime
	}
	if b.Dependencies != nil {
		in.Dependencies = *b.Dependencies
	}
	if b.SupportedTriggers != nil {
		in.SupportedTriggers = *b.SupportedTriggers
	}
	a, err := s.actions.create(s.generateID(), in)
	if writeActionErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		a, ok := s.actions.get(id)
		if !ok {
			writeActionErr(w, errActionNotFound)
			return
		}
		writeJSON(w, http.StatusOK, a)
	case http.MethodPatch:
		var b actionBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, `{"statusCode":400,"error":"Bad Request","message":"invalid body"}`, http.StatusBadRequest)
			return
		}
		p := actionPatch{Name: b.Name, Code: b.Code, Runtime: b.Runtime, Dependencies: b.Dependencies, SupportedTriggers: b.SupportedTriggers}
		if b.Secrets != nil {
			sec := b.secrets()
			p.Secrets = &sec
		}
		a, err := s.actions.update(id, p)
		if writeActionErr(w, err) {
			return
		}
		writeJSON(w, http.StatusOK, a)
	case http.MethodDelete:
		force, _ := strconv.ParseBool(r.URL.Query().Get("force"))
		if writeActionErr(w, s.actions.remove(id, force)) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleTriggerBindings(w http.ResponseWriter, r *http.Request, trigger string) {
	if !triggerKnown(trigger) {
		writeActionErr(w, errBadTrigger)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list := s.actions.listBindings(trigger)
		writeJSON(w, http.StatusOK, map[string]any{"bindings": list, "total": len(list), "page": 0, "per_page": len(list)})
	case http.MethodPatch:
		var body struct {
			Bindings []struct {
				Ref struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"ref"`
				DisplayName string `json:"display_name"`
				Secrets     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"secrets"`
			} `json:"bindings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"statusCode":400,"error":"Bad Request","message":"invalid body"}`, http.StatusBadRequest)
			return
		}
		refs := make([]bindingRef, 0, len(body.Bindings))
		for _, b := range body.Bindings {
			ref := bindingRef{Type: b.Ref.Type, Value: b.Ref.Value, DisplayName: b.DisplayName}
			if b.Secrets != nil {
				ref.Secrets = []ActionSecret{}
				for _, sec := range b.Secrets {
					ref.Secrets = append(ref.Secrets, ActionSecret{Name: sec.Name, value: sec.Value, UpdatedAt: time.Now().UTC()})
				}
			}
			refs = append(refs, ref)
		}
		list, err := s.actions.setBindings(trigger, refs, s.generateID)
		if writeActionErr(w, err) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"bindings": list})
	default:
		methodNotAllowed(w)
	}
}
