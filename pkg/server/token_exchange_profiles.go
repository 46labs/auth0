package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// tokenExchangeProfile is Auth0's wire shape (TestTokenExchangeProfileManager_*.yaml).
type tokenExchangeProfile struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Type             string    `json:"type"`
	SubjectTokenType string    `json:"subject_token_type"`
	ActionID         string    `json:"action_id"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (p *tokenExchangeProfile) Clone() *tokenExchangeProfile {
	out := *p
	return &out
}

type tokenExchangeProfiles struct {
	mu       sync.RWMutex
	profiles map[string]*tokenExchangeProfile
}

var errProfileNotFound = errors.New("Token exchange profile not found.") //nolint:staticcheck // Auth0's recorded message

func (s *Server) registerTokenExchangeProfiles(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/token-exchange-profiles", s.json(s.listTokenExchangeProfiles))
	mux.HandleFunc("POST /api/v2/token-exchange-profiles", s.json(s.createTokenExchangeProfile))
	mux.HandleFunc("GET /api/v2/token-exchange-profiles/{id}", s.json(func(r *http.Request) (int, any, error) {
		s.teps.mu.RLock()
		defer s.teps.mu.RUnlock()
		p, ok := s.teps.profiles[r.PathValue("id")]
		if !ok {
			return 0, nil, errProfileNotFound
		}
		return http.StatusOK, p.Clone(), nil
	}))
	mux.HandleFunc("PATCH /api/v2/token-exchange-profiles/{id}", s.json(s.updateTokenExchangeProfile))
	// 204 even when absent, as recorded (TestTokenExchangeProfileManager_Delete.yaml).
	mux.HandleFunc("DELETE /api/v2/token-exchange-profiles/{id}", s.json(func(r *http.Request) (int, any, error) {
		s.teps.mu.Lock()
		delete(s.teps.profiles, r.PathValue("id"))
		s.teps.mu.Unlock()
		return http.StatusNoContent, nil, nil
	}))
}

// listTokenExchangeProfiles is checkpoint-paginated: from and take, with next
// on a truncated page. Auth0 refuses any other parameter, include_totals too.
func (s *Server) listTokenExchangeProfiles(r *http.Request) (int, any, error) {
	for k := range r.URL.Query() {
		if k != "from" && k != "take" {
			return 0, nil, errors.New("Query validation error: 'Additional properties not allowed: " + k + "'.") //nolint:staticcheck // Auth0's message
		}
	}
	s.teps.mu.RLock()
	all := make([]*tokenExchangeProfile, 0, len(s.teps.profiles))
	for _, p := range s.teps.profiles {
		all = append(all, p.Clone())
	}
	s.teps.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	lo := 0
	if from := r.URL.Query().Get("from"); from != "" {
		lo = sort.Search(len(all), func(i int) bool { return all[i].ID > from })
	}
	take := 50
	if v := r.URL.Query().Get("take"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			return 0, nil, errors.New("Query validation error: take must be an integer from 1 to 100") //nolint:staticcheck // Auth0's message form
		}
		take = n
	}
	hi := min(lo+take, len(all))
	out := map[string]any{"token_exchange_profiles": all[lo:hi]}
	if hi < len(all) {
		out["next"] = all[hi-1].ID
	}
	return http.StatusOK, out, nil
}

type tokenExchangeProfileBody struct {
	Name             *string `json:"name"`
	Type             *string `json:"type"`
	SubjectTokenType *string `json:"subject_token_type"`
	ActionID         *string `json:"action_id"`
}

func decodeProfile(r *http.Request) (tokenExchangeProfileBody, error) {
	var b tokenExchangeProfileBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, errInvalidBody
	}
	return b, nil
}

func (s *Server) createTokenExchangeProfile(r *http.Request) (int, any, error) {
	b, err := decodeProfile(r)
	if err != nil {
		return 0, nil, err
	}
	if b.Name == nil || b.SubjectTokenType == nil || b.ActionID == nil || b.Type == nil {
		return 0, nil, errors.New("name, subject_token_type, action_id and type are required")
	}
	if *b.Type != "custom_authentication" {
		return 0, nil, errors.New("type must be custom_authentication")
	}
	if err := validProfileFields(b); err != nil {
		return 0, nil, err
	}

	now := time.Now().UTC()
	p := &tokenExchangeProfile{
		ID: "tep_" + s.generateID(), Name: *b.Name, Type: *b.Type,
		SubjectTokenType: *b.SubjectTokenType, ActionID: *b.ActionID, CreatedAt: now, UpdatedAt: now,
	}
	// Held across the action check, so a delete cannot orphan the profile.
	s.teps.mu.Lock()
	defer s.teps.mu.Unlock()
	a, ok := s.actions.get(p.ActionID)
	// The deployed version is what runs, so its triggers are the ones checked.
	if !ok || a.DeployedVersion == nil || !slices.ContainsFunc(a.DeployedVersion.SupportedTriggers, func(t ActionTriggerRef) bool { return t.ID == TriggerCustomTokenExchange }) {
		return 0, nil, errors.New("action " + p.ActionID + " is not a deployed custom-token-exchange action")
	}
	if s.teps.subjectTakenLocked(p.SubjectTokenType, "") {
		return 0, nil, errProfileConflict
	}
	s.teps.profiles[p.ID] = p
	return http.StatusCreated, p.Clone(), nil
}

// subjectTakenLocked reports another profile claiming the subject token type.
// Caller holds the lock.
func (t *tokenExchangeProfiles) subjectTakenLocked(subjectType, exceptID string) bool {
	for _, p := range t.profiles {
		if p.ID != exceptID && p.SubjectTokenType == subjectType {
			return true
		}
	}
	return false
}

// usesActionLocked reports a profile running the action. Caller holds the lock.
func (t *tokenExchangeProfiles) usesActionLocked(actionID string) bool {
	for _, p := range t.profiles {
		if p.ActionID == actionID {
			return true
		}
	}
	return false
}

// Namespaces Auth0 keeps for its own token types: URN prefixes, and domains
// with their subdomains.
var (
	reservedURNs    = []string{"urn:ietf:", "urn:auth0:", "urn:okta:"}
	reservedDomains = []string{"auth0.com", "okta.com"}
)

// validProfileFields applies Auth0's documented limits: a 3-50 character
// name, and an 8-100 character https:// or urn: subject token type outside
// the reserved namespaces.
func validProfileFields(b tokenExchangeProfileBody) error {
	if b.Name != nil {
		if n := utf8.RuneCountInString(*b.Name); n < 3 || n > 50 {
			return errors.New("name must be 3 to 50 characters")
		}
	}
	if b.SubjectTokenType == nil {
		return nil
	}
	st := strings.ToLower(*b.SubjectTokenType)
	if n := utf8.RuneCountInString(st); n < 8 || n > 100 || !strings.HasPrefix(st, "https://") && !strings.HasPrefix(st, "urn:") {
		return errors.New("subject_token_type must be an https:// or urn: URI of 8 to 100 characters")
	}
	u, err := url.Parse(st)
	if err != nil || u.Scheme == "https" && u.Host == "" {
		return errors.New("subject_token_type must be a URI")
	}
	for _, ns := range reservedURNs {
		if strings.HasPrefix(st, ns) {
			return errors.New("subject_token_type uses a reserved namespace: " + ns)
		}
	}
	host := u.Hostname()
	for _, d := range reservedDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return errors.New("subject_token_type uses a reserved domain: " + d)
		}
	}
	return nil
}

var errProfileConflict = errors.New("a token exchange profile for this subject_token_type already exists")

// updateTokenExchangeProfile patches name and subject_token_type, the fields
// the SDK sends; action_id and type are immutable.
func (s *Server) updateTokenExchangeProfile(r *http.Request) (int, any, error) {
	b, err := decodeProfile(r)
	if err != nil {
		return 0, nil, err
	}
	if b.ActionID != nil || b.Type != nil {
		return 0, nil, errors.New("action_id and type cannot be changed")
	}
	if err := validProfileFields(b); err != nil {
		return 0, nil, err
	}
	s.teps.mu.Lock()
	defer s.teps.mu.Unlock()
	p, ok := s.teps.profiles[r.PathValue("id")]
	if !ok {
		return 0, nil, errProfileNotFound
	}
	if b.SubjectTokenType != nil {
		if s.teps.subjectTakenLocked(*b.SubjectTokenType, p.ID) {
			return 0, nil, errProfileConflict
		}
		p.SubjectTokenType = *b.SubjectTokenType
	}
	if b.Name != nil {
		p.Name = *b.Name
	}
	p.UpdatedAt = time.Now().UTC()
	return http.StatusOK, p.Clone(), nil
}
