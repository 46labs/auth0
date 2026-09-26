package server

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Actions are the code Auth0 runs at triggers. This mirrors the Actions
// Management API closely enough for a controller built on go-auth0 to
// reconcile against it: create, update, deploy, and bind, then have the
// deployed code run at the trigger. Nothing here persists across restarts;
// a controller reconciles on startup, as it does against a real tenant.

const (
	TriggerPostLogin            = "post-login"
	TriggerCredentialsExchange  = "credentials-exchange"
	TriggerPreUserRegistration  = "pre-user-registration"
	TriggerPostUserRegistration = "post-user-registration"
	TriggerCustomTokenExchange  = "custom-token-exchange"
	TriggerSendPhoneMessage     = "send-phone-message"
	TriggerPostChangePassword   = "post-change-password"
	TriggerPasswordReset        = "password-reset-post-challenge"

	defaultActionRuntime = "node22"
)

var actionRuntimes = []string{"node18", "node22"}

// Trigger is one entry of GET /api/v2/actions/triggers.
type Trigger struct {
	ID                 string   `json:"id"`
	Version            string   `json:"version"`
	Status             string   `json:"status"`
	Runtimes           []string `json:"runtimes"`
	DefaultRuntime     string   `json:"default_runtime"`
	CompatibleTriggers []any    `json:"compatible_triggers"`
}

// supportedTriggers are the triggers this mock knows. Only post-login runs
// code today; the others accept actions and bindings so a controller that
// reconciles several triggers is not refused.
func supportedTriggers() []Trigger {
	mk := func(id, version string) Trigger {
		return Trigger{ID: id, Version: version, Status: "CURRENT", Runtimes: actionRuntimes, DefaultRuntime: defaultActionRuntime, CompatibleTriggers: []any{}}
	}
	return []Trigger{
		mk(TriggerPostLogin, "v3"),
		mk(TriggerCredentialsExchange, "v2"),
		mk(TriggerPreUserRegistration, "v2"),
		mk(TriggerPostUserRegistration, "v2"),
		mk(TriggerCustomTokenExchange, "v1"),
		mk(TriggerSendPhoneMessage, "v2"),
		mk(TriggerPostChangePassword, "v2"),
		mk(TriggerPasswordReset, "v1"),
	}
}

func triggerKnown(id string) bool {
	for _, t := range supportedTriggers() {
		if t.ID == id {
			return true
		}
	}
	return false
}

type ActionTriggerRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Status  string `json:"status,omitempty"`
}

type ActionDependency struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	RegistryURL string `json:"registry_url,omitempty"`
}

// ActionSecret is a secret as the API returns it: the value is write-only,
// as in Auth0, so a controller cannot read it back.
type ActionSecret struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
	value     string
}

type ActionVersion struct {
	ID                string             `json:"id"`
	Code              string             `json:"code"`
	Runtime           string             `json:"runtime"`
	Status            string             `json:"status"`
	Number            int                `json:"number"`
	Deployed          bool               `json:"deployed"`
	Dependencies      []ActionDependency `json:"dependencies"`
	Secrets           []ActionSecret     `json:"secrets"`
	SupportedTriggers []ActionTriggerRef `json:"supported_triggers"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	BuiltAt           time.Time          `json:"built_at"`
}

type Action struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name"`
	SupportedTriggers  []ActionTriggerRef `json:"supported_triggers"`
	Code               string             `json:"code"`
	Dependencies       []ActionDependency `json:"dependencies"`
	Runtime            string             `json:"runtime"`
	Secrets            []ActionSecret     `json:"secrets"`
	Status             string             `json:"status"`
	DeployedVersion    *ActionVersion     `json:"deployed_version,omitempty"`
	AllChangesDeployed bool               `json:"all_changes_deployed"`
	BuiltAt            time.Time          `json:"built_at"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`

	versions []*ActionVersion
	// dirty: changed since the last deploy. Auth0 reports any edit as undeployed.
	dirty bool
}

// clone is a deep copy: the store hands out snapshots, never its own records,
// so a token request encoding or running an action cannot race a PATCH.
func (a *Action) clone() *Action {
	if a == nil {
		return nil
	}
	c := *a
	c.SupportedTriggers = append([]ActionTriggerRef(nil), a.SupportedTriggers...)
	c.Dependencies = append([]ActionDependency(nil), a.Dependencies...)
	c.Secrets = append([]ActionSecret(nil), a.Secrets...)
	c.DeployedVersion = a.DeployedVersion.clone()
	c.versions = nil
	return &c
}

func (v *ActionVersion) clone() *ActionVersion {
	if v == nil {
		return nil
	}
	c := *v
	c.Dependencies = append([]ActionDependency(nil), v.Dependencies...)
	c.Secrets = append([]ActionSecret(nil), v.Secrets...)
	c.SupportedTriggers = append([]ActionTriggerRef(nil), v.SupportedTriggers...)
	return &c
}

func (b *ActionBinding) clone() *ActionBinding {
	c := *b
	c.Action = b.Action.clone()
	c.Secrets = append([]ActionSecret(nil), b.Secrets...)
	return &c
}

// ActionBinding places an action on a trigger, in order.
type ActionBinding struct {
	ID          string         `json:"id"`
	TriggerID   string         `json:"trigger_id"`
	Action      *Action        `json:"action"`
	DisplayName string         `json:"display_name"`
	Secrets     []ActionSecret `json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type actionStore struct {
	mu       sync.RWMutex
	actions  map[string]*Action
	bindings map[string][]*ActionBinding
}

func newActionStore() *actionStore {
	return &actionStore{actions: map[string]*Action{}, bindings: map[string][]*ActionBinding{}}
}

var (
	errActionNotFound  = errors.New("action not found")
	errActionNameTaken = errors.New("an action with this name already exists")
	errActionNotBuilt  = errors.New("action must be built before it can be deployed")
	errActionBound     = errors.New("action is bound to a trigger; unbind it first")
	errBadTrigger      = errors.New("unknown trigger")
)

// secretValues merges binding secrets over action secrets by name.
func secretValues(a *Action, b *ActionBinding) map[string]string {
	out := map[string]string{}
	for _, s := range a.Secrets {
		out[s.Name] = s.value
	}
	if b != nil {
		for _, s := range b.Secrets {
			out[s.Name] = s.value
		}
	}
	return out
}

func (st *actionStore) create(id string, in Action) (*Action, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("name is required")
	}
	for _, a := range st.actions {
		if a.Name == in.Name {
			return nil, errActionNameTaken
		}
	}
	for _, t := range in.SupportedTriggers {
		if !triggerKnown(t.ID) {
			return nil, errBadTrigger
		}
	}
	now := time.Now().UTC()
	a := &Action{
		ID: id, Name: in.Name, SupportedTriggers: in.SupportedTriggers, Code: in.Code,
		Dependencies: nonNilDeps(in.Dependencies), Runtime: in.Runtime, Secrets: stampSecrets(in.Secrets, now),
		// The mock builds synchronously: a created action is ready to deploy.
		Status: "built", BuiltAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if a.Runtime == "" {
		a.Runtime = defaultActionRuntime
	}
	if a.SupportedTriggers == nil {
		a.SupportedTriggers = []ActionTriggerRef{}
	}
	st.actions[id] = a
	return a.clone(), nil
}

func nonNilDeps(d []ActionDependency) []ActionDependency {
	if d == nil {
		return []ActionDependency{}
	}
	return d
}

func stampSecrets(in []ActionSecret, now time.Time) []ActionSecret {
	out := make([]ActionSecret, 0, len(in))
	for _, s := range in {
		out = append(out, ActionSecret{Name: s.Name, UpdatedAt: now, value: s.value})
	}
	return out
}

func (st *actionStore) get(id string) (*Action, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	a, ok := st.actions[id]
	return a.clone(), ok
}

// list returns actions, optionally filtered, in creation order.
func (st *actionStore) list(name, trigger string, deployed *bool) []*Action {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := []*Action{}
	for _, a := range st.actions {
		if name != "" && a.Name != name {
			continue
		}
		if trigger != "" && !hasTrigger(a, trigger) {
			continue
		}
		if deployed != nil && (a.DeployedVersion != nil) != *deployed {
			continue
		}
		out = append(out, a.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func hasTrigger(a *Action, trigger string) bool {
	for _, t := range a.SupportedTriggers {
		if t.ID == trigger {
			return true
		}
	}
	return false
}

// actionPatch is what PATCH may change; nil means untouched.
type actionPatch struct {
	Name              *string
	Code              *string
	Runtime           *string
	Dependencies      *[]ActionDependency
	Secrets           *[]ActionSecret
	SupportedTriggers *[]ActionTriggerRef
}

func (st *actionStore) update(id string, p actionPatch) (*Action, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	a, ok := st.actions[id]
	if !ok {
		return nil, errActionNotFound
	}
	if p.Name != nil && *p.Name != a.Name {
		for _, o := range st.actions {
			if o.Name == *p.Name {
				return nil, errActionNameTaken
			}
		}
		a.Name = *p.Name
	}
	if p.Code != nil {
		a.Code = *p.Code
	}
	if p.Runtime != nil {
		a.Runtime = *p.Runtime
	}
	if p.Dependencies != nil {
		a.Dependencies = nonNilDeps(*p.Dependencies)
	}
	now := time.Now().UTC()
	if p.Secrets != nil {
		// Secrets merge by name: an omitted secret keeps its value.
		kept := map[string]ActionSecret{}
		for _, s := range a.Secrets {
			kept[s.Name] = s
		}
		for _, s := range *p.Secrets {
			kept[s.Name] = ActionSecret{Name: s.Name, UpdatedAt: now, value: s.value}
		}
		merged := make([]ActionSecret, 0, len(kept))
		for _, s := range kept {
			merged = append(merged, s)
		}
		sort.Slice(merged, func(i, j int) bool { return merged[i].Name < merged[j].Name })
		a.Secrets = merged
	}
	if p.SupportedTriggers != nil {
		for _, t := range *p.SupportedTriggers {
			if !triggerKnown(t.ID) {
				return nil, errBadTrigger
			}
		}
		a.SupportedTriggers = *p.SupportedTriggers
	}
	a.UpdatedAt = now
	a.BuiltAt = now
	a.Status = "built"
	a.dirty = true
	a.AllChangesDeployed = false
	return a.clone(), nil
}

func (st *actionStore) deploy(id, versionID string) (*ActionVersion, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	a, ok := st.actions[id]
	if !ok {
		return nil, errActionNotFound
	}
	if a.Status != "built" {
		return nil, errActionNotBuilt
	}
	now := time.Now().UTC()
	for _, v := range a.versions {
		v.Deployed = false
	}
	v := &ActionVersion{
		ID: versionID, Code: a.Code, Runtime: a.Runtime, Status: "BUILT", Number: len(a.versions) + 1, Deployed: true,
		Dependencies: a.Dependencies, Secrets: a.Secrets, SupportedTriggers: a.SupportedTriggers,
		CreatedAt: now, UpdatedAt: now, BuiltAt: now,
	}
	a.versions = append(a.versions, v)
	a.DeployedVersion = v
	a.dirty = false
	a.AllChangesDeployed = true
	a.UpdatedAt = now
	return v.clone(), nil
}

func (st *actionStore) versions(id string) ([]*ActionVersion, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	a, ok := st.actions[id]
	if !ok {
		return nil, errActionNotFound
	}
	out := make([]*ActionVersion, 0, len(a.versions))
	for _, v := range a.versions {
		out = append(out, v.clone())
	}
	return out, nil
}

func (st *actionStore) remove(id string, force bool) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.actions[id]; !ok {
		return errActionNotFound
	}
	for trigger, list := range st.bindings {
		for _, b := range list {
			if b.Action.ID == id {
				if !force {
					return errActionBound
				}
				st.bindings[trigger] = removeBinding(list, id)
				break
			}
		}
	}
	delete(st.actions, id)
	return nil
}

func removeBinding(list []*ActionBinding, actionID string) []*ActionBinding {
	out := make([]*ActionBinding, 0, len(list))
	for _, b := range list {
		if b.Action.ID != actionID {
			out = append(out, b)
		}
	}
	return out
}

func (st *actionStore) listBindings(trigger string) []*ActionBinding {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*ActionBinding, 0, len(st.bindings[trigger]))
	for _, b := range st.bindings[trigger] {
		out = append(out, b.clone())
	}
	return out
}

// bindingRef is one entry of PATCH /api/v2/actions/triggers/{id}/bindings.
type bindingRef struct {
	Type        string // action_id | action_name | binding_id
	Value       string
	DisplayName string
	Secrets     []ActionSecret
}

// setBindings replaces a trigger's bindings with the given list, in order,
// keeping ids for bindings that already existed.
func (st *actionStore) setBindings(trigger string, refs []bindingRef, newID func() string) ([]*ActionBinding, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !triggerKnown(trigger) {
		return nil, errBadTrigger
	}
	existing := map[string]*ActionBinding{}
	for _, b := range st.bindings[trigger] {
		existing[b.Action.ID] = b
	}
	now := time.Now().UTC()
	out := make([]*ActionBinding, 0, len(refs))
	for _, ref := range refs {
		var a *Action
		switch ref.Type {
		case "action_id":
			a = st.actions[ref.Value]
		case "action_name":
			for _, x := range st.actions {
				if x.Name == ref.Value {
					a = x
				}
			}
		case "binding_id":
			for _, b := range st.bindings[trigger] {
				if b.ID == ref.Value {
					a = b.Action
				}
			}
		}
		if a == nil {
			return nil, errActionNotFound
		}
		if !hasTrigger(a, trigger) {
			return nil, errBadTrigger
		}
		b := existing[a.ID]
		if b == nil {
			b = &ActionBinding{ID: newID(), TriggerID: trigger, Action: a, CreatedAt: now}
		}
		b.DisplayName = ref.DisplayName
		if b.DisplayName == "" {
			b.DisplayName = a.Name
		}
		if ref.Secrets != nil {
			b.Secrets = stampSecrets(ref.Secrets, now)
		}
		b.UpdatedAt = now
		out = append(out, b)
	}
	st.bindings[trigger] = out
	snap := make([]*ActionBinding, 0, len(out))
	for _, b := range out {
		snap = append(snap, b.clone())
	}
	return snap, nil
}
