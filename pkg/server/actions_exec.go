package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/golang-jwt/jwt/v5"
)

// actionTimeout bounds one Action run, as Auth0 does.
const actionTimeout = 20 * time.Second

// accessDenied is what api.access.deny(reason) produces.
type accessDenied struct {
	Reason string
}

// postLoginRequest is what the Action sees of the request that reached the
// trigger: the /authorize query for a code exchange, the token form otherwise.
type postLoginRequest struct {
	Protocol    string
	Method      string
	IP          string
	Host        string
	UA          string
	Query       map[string]string
	Body        map[string]string
	Scopes      []string
	RedirectURI string
	LoginHint   string
}

// runPostLoginActions runs every action bound to post-login, in order, with
// the user, client, and request in the event and an api that can add claims,
// change metadata, or deny the login. Actions bound but not deployed are
// skipped, as in Auth0. The first deny wins; a throwing Action fails the login.
func (s *Server) runPostLoginActions(user *config.User, client *config.Client, req postLoginRequest, idClaims, accessClaims jwt.MapClaims) *accessDenied {
	for _, b := range s.actions.listBindings(TriggerPostLogin) {
		a := b.Action
		if a.DeployedVersion == nil {
			continue
		}
		denied, err := s.runOnePostLogin(a, b, user, client, req, idClaims, accessClaims)
		if err != nil {
			log.Printf("action %q failed: %v", a.Name, err)
			return &accessDenied{Reason: fmt.Sprintf("action %s failed: %v", a.Name, err)}
		}
		if denied != nil {
			return denied
		}
	}
	return nil
}

func (s *Server) runOnePostLogin(a *Action, b *ActionBinding, user *config.User, client *config.Client, req postLoginRequest, idClaims, accessClaims jwt.MapClaims) (*accessDenied, error) {
	loop := eventloop.NewEventLoop()
	loop.Start()
	defer loop.Stop()

	type outcome struct {
		denied *accessDenied
		err    error
	}
	done := make(chan outcome, 1)
	vmReady := make(chan *goja.Runtime, 1)

	loop.RunOnLoop(func(vm *goja.Runtime) {
		vmReady <- vm
		var denied *accessDenied
		finish := func(err error) {
			select {
			case done <- outcome{denied: denied, err: err}:
			default:
			}
		}
		s.installRuntime(vm, loop, a, b, user, client, req)
		api := vm.NewObject()
		idTok := vm.NewObject()
		_ = idTok.Set("setCustomClaim", func(name string, value goja.Value) { idClaims[name] = value.Export() })
		accTok := vm.NewObject()
		_ = accTok.Set("setCustomClaim", func(name string, value goja.Value) { accessClaims[name] = value.Export() })
		access := vm.NewObject()
		_ = access.Set("deny", func(reason string) {
			if denied == nil {
				denied = &accessDenied{Reason: reason}
			}
		})
		userAPI := vm.NewObject()
		_ = userAPI.Set("setAppMetadata", func(key string, value goja.Value) { s.setAppMetadata(user, key, value.Export()) })
		_ = userAPI.Set("setUserMetadata", func(key string, value goja.Value) { s.setUserMetadata(user, key, value.Export()) })
		_ = api.Set("idToken", idTok)
		_ = api.Set("accessToken", accTok)
		_ = api.Set("access", access)
		_ = api.Set("user", userAPI)

		// CommonJS: exports.onExecutePostLogin = async (event, api) => {...}
		wrapped := "(function(exports, module, require) {\n" + a.DeployedVersion.Code + "\n})"
		fnVal, err := vm.RunString(wrapped)
		if err != nil {
			finish(fmt.Errorf("compile: %w", err))
			return
		}
		wrap, _ := goja.AssertFunction(fnVal)
		exports := vm.NewObject()
		module := vm.NewObject()
		_ = module.Set("exports", exports)
		if _, err := wrap(goja.Undefined(), exports, module, vm.Get("require")); err != nil {
			finish(fmt.Errorf("load: %w", err))
			return
		}
		handlerVal := exports.Get("onExecutePostLogin")
		if me, ok := module.Get("exports").(*goja.Object); ok && me != exports {
			handlerVal = me.Get("onExecutePostLogin")
		}
		handler, ok := goja.AssertFunction(handlerVal)
		if !ok {
			finish(fmt.Errorf("action %q does not export onExecutePostLogin", a.Name))
			return
		}
		result, err := handler(goja.Undefined(), vm.Get("event"), api)
		if err != nil {
			finish(fmt.Errorf("run: %w", err))
			return
		}
		// Await whatever came back (a Promise from an async handler).
		_ = vm.Set("__result", result)
		_ = vm.Set("__ok", func() { finish(nil) })
		_ = vm.Set("__fail", func(v goja.Value) { finish(fmt.Errorf("run: %s", v.String())) })
		if _, err := vm.RunString(`Promise.resolve(__result).then(__ok, __fail)`); err != nil {
			finish(fmt.Errorf("await: %w", err))
		}
	})

	var vm *goja.Runtime
	select {
	case vm = <-vmReady:
	case <-time.After(actionTimeout):
		return nil, fmt.Errorf("timed out starting after %s", actionTimeout)
	}
	select {
	case out := <-done:
		return out.denied, out.err
	case <-time.After(actionTimeout):
		vm.Interrupt("action timed out")
		return nil, fmt.Errorf("timed out after %s", actionTimeout)
	}
}

// installRuntime gives the Action its globals: event, console, fetch, require.
func (s *Server) installRuntime(vm *goja.Runtime, loop *eventloop.EventLoop, a *Action, b *ActionBinding, user *config.User, client *config.Client, req postLoginRequest) {
	_ = vm.Set("event", s.buildEvent(vm, a, b, user, client, req))

	console := vm.NewObject()
	logf := func(level string) func(args ...goja.Value) {
		return func(args ...goja.Value) {
			parts := make([]string, 0, len(args))
			for _, v := range args {
				parts = append(parts, v.String())
			}
			log.Printf("action %s %s: %s", a.Name, level, strings.Join(parts, " "))
		}
	}
	_ = console.Set("log", logf("log"))
	_ = console.Set("info", logf("info"))
	_ = console.Set("warn", logf("warn"))
	_ = console.Set("error", logf("error"))
	_ = vm.Set("console", console)

	// npm dependencies are not installed here; fetch is the supported way out.
	_ = vm.Set("require", func(name string) goja.Value {
		panic(vm.NewGoError(fmt.Errorf("module %q is not available in the auth0 mock; use the global fetch", name)))
	})

	_ = vm.Set("fetch", func(call goja.FunctionCall) goja.Value {
		target := call.Argument(0).String()
		method := http.MethodGet
		headers := http.Header{}
		var body io.Reader
		if init, ok := call.Argument(1).(*goja.Object); ok {
			if m := init.Get("method"); m != nil && !goja.IsUndefined(m) {
				method = strings.ToUpper(m.String())
			}
			if h, ok := init.Get("headers").(*goja.Object); ok {
				for _, k := range h.Keys() {
					headers.Set(k, h.Get(k).String())
				}
			}
			if bd := init.Get("body"); bd != nil && !goja.IsUndefined(bd) && !goja.IsNull(bd) {
				body = strings.NewReader(bd.String())
			}
		}
		promise, resolve, reject := vm.NewPromise()
		go func() {
			status, statusText, respHeaders, data, err := doFetch(method, target, headers, body)
			loop.RunOnLoop(func(vm *goja.Runtime) {
				if err != nil {
					_ = reject(vm.NewGoError(err))
					return
				}
				resp := vm.NewObject()
				_ = resp.Set("ok", status >= 200 && status < 300)
				_ = resp.Set("status", status)
				_ = resp.Set("statusText", statusText)
				hdr := vm.NewObject()
				_ = hdr.Set("get", func(name string) goja.Value {
					v := respHeaders.Get(name)
					if v == "" {
						return goja.Null()
					}
					return vm.ToValue(v)
				})
				_ = resp.Set("headers", hdr)
				_ = resp.Set("text", func() goja.Value {
					p, res, _ := vm.NewPromise()
					_ = res(vm.ToValue(string(data)))
					return vm.ToValue(p)
				})
				_ = resp.Set("json", func() goja.Value {
					p, res, rej := vm.NewPromise()
					var v any
					if err := json.Unmarshal(data, &v); err != nil {
						_ = rej(vm.NewGoError(err))
					} else {
						_ = res(vm.ToValue(v))
					}
					return vm.ToValue(p)
				})
				_ = resolve(resp)
			})
		}()
		return vm.ToValue(promise)
	})
}

var fetchClient = &http.Client{Timeout: 10 * time.Second}

func doFetch(method, target string, headers http.Header, body io.Reader) (int, string, http.Header, []byte, error) {
	if _, err := url.ParseRequestURI(target); err != nil {
		return 0, "", nil, nil, fmt.Errorf("fetch: %w", err)
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return 0, "", nil, nil, err
	}
	req.Header = headers
	resp, err := fetchClient.Do(req)
	if err != nil {
		return 0, "", nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, "", nil, nil, err
	}
	return resp.StatusCode, http.StatusText(resp.StatusCode), resp.Header, data, nil
}

// buildEvent is the post-login event object, shaped like Auth0's.
func (s *Server) buildEvent(vm *goja.Runtime, a *Action, b *ActionBinding, user *config.User, client *config.Client, req postLoginRequest) goja.Value {
	appMeta := map[string]any{}
	if user.AppMetadata.TenantID != "" {
		appMeta["tenant_id"] = user.AppMetadata.TenantID
	}
	if user.AppMetadata.Role != "" {
		appMeta["role"] = user.AppMetadata.Role
	}
	s.mu.RLock()
	for k, v := range s.appMetaExtra[user.ID] {
		appMeta[k] = v
	}
	var org *config.Organization
	if user.AppMetadata.TenantID != "" {
		org = s.organizations[user.AppMetadata.TenantID]
	}
	s.mu.RUnlock()
	userMeta := map[string]any{}
	for k, v := range user.UserMetadata {
		userMeta[k] = v
	}
	identities := []any{}
	for _, id := range user.Identities {
		identities = append(identities, map[string]any{"connection": id.Connection, "provider": id.Provider, "user_id": id.UserID, "isSocial": id.IsSocial})
	}
	ev := map[string]any{
		"user": map[string]any{
			"user_id":        user.ID,
			"email":          user.Email,
			"email_verified": user.EmailVerified,
			"phone_number":   user.Phone,
			"name":           user.Name,
			"picture":        user.Picture,
			"app_metadata":   appMeta,
			"user_metadata":  userMeta,
			"identities":     identities,
		},
		"client":     map[string]any{"client_id": "", "name": "", "metadata": map[string]any{}},
		"connection": map[string]any{"id": "", "name": "", "strategy": ""},
		"request": map[string]any{
			"method":     req.Method,
			"ip":         req.IP,
			"hostname":   req.Host,
			"user_agent": req.UA,
			"query":      stringMap(req.Query),
			"body":       stringMap(req.Body),
			"geoip":      map[string]any{},
		},
		"transaction": map[string]any{
			"protocol":         req.Protocol,
			"requested_scopes": req.Scopes,
			"redirect_uri":     req.RedirectURI,
			"login_hint":       req.LoginHint,
			"ui_locales":       []any{},
			"locale":           "en",
		},
		"authorization":  map[string]any{"roles": []any{}},
		"tenant":         map[string]any{"id": "mock"},
		"secrets":        secretValues(a, b),
		"stats":          map[string]any{"logins_count": 1},
		"authentication": map[string]any{"methods": []any{map[string]any{"name": "passwordless", "timestamp": time.Now().UTC().Format(time.RFC3339)}}},
	}
	if client != nil {
		ev["client"] = map[string]any{"client_id": client.ClientID, "name": client.Name, "metadata": map[string]any{}}
	} else if id := req.Query["client_id"]; id != "" {
		ev["client"] = map[string]any{"client_id": id, "name": "", "metadata": map[string]any{}}
	}
	if len(user.Identities) > 0 {
		ev["connection"] = map[string]any{"id": "con_" + user.Identities[0].Connection, "name": user.Identities[0].Connection, "strategy": user.Identities[0].Provider}
	}
	if org != nil {
		ev["organization"] = map[string]any{"id": org.ID, "name": org.Name, "display_name": org.DisplayName, "metadata": map[string]any{}}
	}
	return vm.ToValue(ev)
}

func stringMap(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// setAppMetadata persists api.user.setAppMetadata. tenant_id and role are
// real fields; anything else lives beside the user for the event's sake.
func (s *Server) setAppMetadata(user *config.User, key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch key {
	case "tenant_id":
		user.AppMetadata.TenantID = fmt.Sprint(value)
	case "role":
		user.AppMetadata.Role = fmt.Sprint(value)
	default:
		if s.appMetaExtra[user.ID] == nil {
			s.appMetaExtra[user.ID] = map[string]any{}
		}
		if value == nil {
			delete(s.appMetaExtra[user.ID], key)
		} else {
			s.appMetaExtra[user.ID][key] = value
		}
	}
	if u := s.users[user.ID]; u != nil && u != user {
		u.AppMetadata = user.AppMetadata
	}
}

func (s *Server) setUserMetadata(user *config.User, key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user.UserMetadata == nil {
		user.UserMetadata = map[string]interface{}{}
	}
	if value == nil {
		delete(user.UserMetadata, key)
	} else {
		user.UserMetadata[key] = value
	}
	if u := s.users[user.ID]; u != nil && u != user {
		u.UserMetadata = user.UserMetadata
	}
}

// writeAccessDenied answers a token request an Action denied, as Auth0 does.
func writeAccessDenied(w http.ResponseWriter, d *accessDenied) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied", "error_description": d.Reason})
}

// requestFromToken is the post-login request for a token exchange: the
// original /authorize query when there was one, else the token form.
func (s *Server) requestFromToken(r *http.Request, code, protocol string) postLoginRequest {
	req := postLoginRequest{Protocol: protocol, Method: r.Method, Host: r.Host, UA: r.UserAgent(), IP: clientIP(r), Query: map[string]string{}, Body: map[string]string{}}
	for k, v := range r.Form {
		if len(v) > 0 && k != "code_verifier" && k != "client_secret" {
			req.Body[k] = v[0]
		}
	}
	if code != "" {
		s.mu.RLock()
		raw := s.authQuery[code]
		s.mu.RUnlock()
		if q, err := url.ParseQuery(raw); err == nil {
			for k, v := range q {
				if len(v) > 0 {
					req.Query[k] = v[0]
				}
			}
			req.Scopes = strings.Fields(q.Get("scope"))
			req.RedirectURI = q.Get("redirect_uri")
			req.LoginHint = q.Get("login_hint")
		}
	}
	return req
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
