package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// registerActionsAPI mounts the Actions Management API. Method-and-pattern
// routes (Go 1.22 ServeMux) do the dispatch; the handlers only do the work.
func (s *Server) registerActionsAPI(mux *http.ServeMux) {
	mux.HandleFunc("OPTIONS /api/v2/actions/", func(w http.ResponseWriter, r *http.Request) { s.setCORS(w, r) })
	mux.HandleFunc("GET /api/v2/actions/triggers", s.json(func(_ *http.Request) (int, any, error) {
		return http.StatusOK, map[string]any{"triggers": supportedTriggers()}, nil
	}))
	mux.HandleFunc("GET /api/v2/actions/triggers/{trigger}/bindings", s.json(s.listBindings))
	mux.HandleFunc("PATCH /api/v2/actions/triggers/{trigger}/bindings", s.json(s.updateBindings))
	mux.HandleFunc("GET /api/v2/actions/actions", s.json(s.listActions))
	mux.HandleFunc("POST /api/v2/actions/actions", s.json(s.createAction))
	mux.HandleFunc("GET /api/v2/actions/actions/{id}", s.json(s.getAction))
	mux.HandleFunc("PATCH /api/v2/actions/actions/{id}", s.json(s.updateAction))
	mux.HandleFunc("DELETE /api/v2/actions/actions/{id}", s.json(s.deleteAction))
	mux.HandleFunc("POST /api/v2/actions/actions/{id}/deploy", s.json(func(r *http.Request) (int, any, error) {
		v, err := s.actions.deploy(r.PathValue("id"), s.generateID())
		return http.StatusOK, v, err
	}))
	mux.HandleFunc("GET /api/v2/actions/actions/{id}/versions", s.json(func(r *http.Request) (int, any, error) {
		vs, err := s.actions.versions(r.PathValue("id"))
		return http.StatusOK, page("versions", vs), err
	}))
}

// json adapts a handler that returns (status, body, error) to the Management
// API's JSON conventions, including Auth0's error envelope.
func (s *Server) json(fn func(*http.Request) (int, any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.setCORS(w, r)
		w.Header().Set("Content-Type", "application/json")
		status, body, err := fn(r)
		if err != nil {
			status, text := actionErrStatus(err)
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": status, "error": text, "message": err.Error()})
			return
		}
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
}

func actionErrStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errActionNotFound):
		return http.StatusNotFound, "Not Found"
	case errors.Is(err, errActionNameTaken), errors.Is(err, errActionBound):
		return http.StatusConflict, "Conflict"
	default:
		return http.StatusBadRequest, "Bad Request"
	}
}

var errInvalidBody = errors.New("invalid body")

// page wraps a list the way Auth0 does; the mock never pages.
func page[T any](key string, items []T) map[string]any {
	return map[string]any{key: items, "total": len(items), "page": 0, "per_page": len(items)}
}

// actionBody is the wire shape of POST and PATCH /api/v2/actions/actions.
type actionBody struct {
	Name              *string             `json:"name"`
	SupportedTriggers *[]ActionTriggerRef `json:"supported_triggers"`
	Code              *string             `json:"code"`
	Dependencies      *[]ActionDependency `json:"dependencies"`
	Runtime           *string             `json:"runtime"`
	Secrets           *[]secretBody       `json:"secrets"`
}

type secretBody struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func toSecrets(in []secretBody) []ActionSecret {
	out := make([]ActionSecret, 0, len(in))
	for _, s := range in {
		out = append(out, ActionSecret{Name: s.Name, value: s.Value})
	}
	return out
}

func (b actionBody) patch() actionPatch {
	p := actionPatch{Name: b.Name, Code: b.Code, Runtime: b.Runtime, Dependencies: b.Dependencies, SupportedTriggers: b.SupportedTriggers}
	if b.Secrets != nil {
		sec := toSecrets(*b.Secrets)
		p.Secrets = &sec
	}
	return p
}

func decode[T any](r *http.Request) (T, error) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return v, errInvalidBody
	}
	return v, nil
}

func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

func (s *Server) listActions(r *http.Request) (int, any, error) {
	q := r.URL.Query()
	var deployed *bool
	if v := q.Get("deployed"); v != "" {
		b, _ := strconv.ParseBool(v)
		deployed = &b
	}
	return http.StatusOK, page("actions", s.actions.list(q.Get("actionName"), q.Get("triggerId"), deployed)), nil
}

func (s *Server) createAction(r *http.Request) (int, any, error) {
	b, err := decode[actionBody](r)
	if err != nil {
		return 0, nil, err
	}
	in := Action{Name: deref(b.Name), Code: deref(b.Code), Runtime: deref(b.Runtime), Dependencies: deref(b.Dependencies), SupportedTriggers: deref(b.SupportedTriggers)}
	if b.Secrets != nil {
		in.Secrets = toSecrets(*b.Secrets)
	}
	a, err := s.actions.create(s.generateID(), in)
	return http.StatusCreated, a, err
}

func (s *Server) getAction(r *http.Request) (int, any, error) {
	a, ok := s.actions.get(r.PathValue("id"))
	if !ok {
		return 0, nil, errActionNotFound
	}
	return http.StatusOK, a, nil
}

func (s *Server) updateAction(r *http.Request) (int, any, error) {
	b, err := decode[actionBody](r)
	if err != nil {
		return 0, nil, err
	}
	a, err := s.actions.update(r.PathValue("id"), b.patch())
	return http.StatusOK, a, err
}

func (s *Server) deleteAction(r *http.Request) (int, any, error) {
	force, _ := strconv.ParseBool(r.URL.Query().Get("force"))
	return http.StatusNoContent, nil, s.actions.remove(r.PathValue("id"), force)
}

func (s *Server) listBindings(r *http.Request) (int, any, error) {
	trigger := r.PathValue("trigger")
	if !triggerKnown(trigger) {
		return 0, nil, errBadTrigger
	}
	return http.StatusOK, page("bindings", s.actions.listBindings(trigger)), nil
}

func (s *Server) updateBindings(r *http.Request) (int, any, error) {
	body, err := decode[struct {
		Bindings []struct {
			Ref struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"ref"`
			DisplayName string       `json:"display_name"`
			Secrets     []secretBody `json:"secrets"`
		} `json:"bindings"`
	}](r)
	if err != nil {
		return 0, nil, err
	}
	refs := make([]bindingRef, 0, len(body.Bindings))
	for _, b := range body.Bindings {
		ref := bindingRef{Type: b.Ref.Type, Value: b.Ref.Value, DisplayName: b.DisplayName}
		if b.Secrets != nil {
			ref.Secrets = toSecrets(b.Secrets)
		}
		refs = append(refs, ref)
	}
	list, err := s.actions.setBindings(r.PathValue("trigger"), refs, s.generateID)
	return http.StatusOK, map[string]any{"bindings": list}, err
}
