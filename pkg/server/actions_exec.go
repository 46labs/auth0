package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/buffer"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
	jsurl "github.com/dop251/goja_nodejs/url"
	"github.com/golang-jwt/jwt/v5"
)

// actionTimeout bounds one Action run, as Auth0 does.
const actionTimeout = 20 * time.Second

// errAccessDenied is what api.access.deny(reason) produces; the reason is the message.
type errAccessDenied struct{ reason string }

func (e *errAccessDenied) Error() string { return e.reason }

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

// postLogin runs the declarative claims block and then every deployed
// post-login Action. It answers the token request itself when an Action
// denies or fails, and reports whether the caller may go on to issue tokens.
func (s *Server) postLogin(w http.ResponseWriter, r *http.Request, user *config.User, clientID, orgID, authorizeQuery, protocol string, idClaims, accessClaims jwt.MapClaims) bool {
	client := s.lookupClient(clientID)
	s.applyPostLogin(user, client, orgID, idClaims, accessClaims)
	req := requestFromToken(r, authorizeQuery, protocol)
	for _, b := range s.actions.listBindings(TriggerPostLogin) {
		if b.Action.DeployedVersion == nil {
			continue // bound but not deployed: Auth0 skips it too
		}
		if err := s.runPostLoginAction(b, user, client, orgID, req, idClaims, accessClaims); err != nil {
			var denied *errAccessDenied
			if !errors.As(err, &denied) {
				// A throwing Action fails the login, as in Auth0.
				log.Printf("action %q failed: %v", b.Action.Name, err)
				denied = &errAccessDenied{reason: fmt.Sprintf("action %s failed: %v", b.Action.Name, err)}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied", "error_description": denied.reason})
			return false
		}
	}
	return true
}

// runPostLoginAction runs one Action's deployed code to completion, awaiting
// an async handler, within actionTimeout. It returns *errAccessDenied when the
// code called api.access.deny.
func (s *Server) runPostLoginAction(b *ActionBinding, user *config.User, client *config.Client, orgID string, req postLoginRequest, idClaims, accessClaims jwt.MapClaims) error {
	a := b.Action
	registry := require.NewRegistry()
	registry.RegisterNativeModule(console.ModuleName, console.RequireWithPrinter(actionPrinter{a.Name}))
	loop := eventloop.NewEventLoop(eventloop.WithRegistry(registry), eventloop.EnableConsole(false))

	var (
		runErr error
		denied *errAccessDenied
		vm     *goja.Runtime
	)
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	timer := time.AfterFunc(actionTimeout, func() {
		if vm != nil {
			vm.Interrupt("action timed out")
		}
	})
	defer timer.Stop()

	// Run blocks until the loop has nothing left to do: the handler has
	// returned and every promise and timer it started has settled.
	loop.Run(func(rt *goja.Runtime) {
		vm = rt
		console.Enable(vm)
		jsurl.Enable(vm)
		buffer.Enable(vm)
		s.installRequire(vm)
		installFetch(ctx, vm, loop)
		_ = vm.Set("event", vm.ToValue(s.buildEvent(a, b, user, client, orgID, req)))
		api := s.newActionAPI(vm, user, idClaims, accessClaims, func(reason string) {
			if denied == nil {
				denied = &errAccessDenied{reason: reason}
			}
		})
		handler, err := loadPostLoginHandler(vm, a)
		if err != nil {
			runErr = err
			return
		}
		result, err := handler(goja.Undefined(), vm.Get("event"), api)
		if err != nil {
			runErr = fmt.Errorf("run: %w", err)
			return
		}
		// An async handler returns a Promise; record a rejection when it settles.
		_ = vm.Set("__result", result)
		_ = vm.Set("__fail", func(v goja.Value) { runErr = fmt.Errorf("run: %s", v.String()) })
		if _, err := vm.RunString(`Promise.resolve(__result).catch(__fail)`); err != nil {
			runErr = fmt.Errorf("await: %w", err)
		}
	})
	if runErr != nil {
		return runErr
	}
	if denied != nil {
		return denied
	}
	return nil
}

// loadPostLoginHandler evaluates the Action as a CommonJS module and returns
// its onExecutePostLogin export.
func loadPostLoginHandler(vm *goja.Runtime, a *Action) (goja.Callable, error) {
	wrapped := "(function(exports, module, require) {\n" + a.DeployedVersion.Code + "\n})"
	fnVal, err := vm.RunString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	wrap, _ := goja.AssertFunction(fnVal)
	exports := vm.NewObject()
	module := vm.NewObject()
	_ = module.Set("exports", exports)
	if _, err := wrap(goja.Undefined(), exports, module, vm.Get("require")); err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	target := exports
	if me, ok := module.Get("exports").(*goja.Object); ok {
		target = me
	}
	handler, ok := goja.AssertFunction(target.Get("onExecutePostLogin"))
	if !ok {
		return nil, fmt.Errorf("action %q does not export onExecutePostLogin", a.Name)
	}
	return handler, nil
}

// newActionAPI is the `api` object: claims, denial, metadata.
func (s *Server) newActionAPI(vm *goja.Runtime, user *config.User, idClaims, accessClaims jwt.MapClaims, deny func(string)) *goja.Object {
	claimSetter := func(claims jwt.MapClaims) *goja.Object {
		o := vm.NewObject()
		_ = o.Set("setCustomClaim", func(name string, value goja.Value) { claims[name] = value.Export() })
		return o
	}
	access := vm.NewObject()
	_ = access.Set("deny", deny)
	userAPI := vm.NewObject()
	_ = userAPI.Set("setAppMetadata", func(key string, value goja.Value) { s.setAppMetadata(user, key, value.Export()) })
	_ = userAPI.Set("setUserMetadata", func(key string, value goja.Value) { s.setUserMetadata(user, key, value.Export()) })
	api := vm.NewObject()
	_ = api.Set("idToken", claimSetter(idClaims))
	_ = api.Set("accessToken", claimSetter(accessClaims))
	_ = api.Set("access", access)
	_ = api.Set("user", userAPI)
	return api
}

// actionPrinter routes an Action's console output to the server log.
type actionPrinter struct{ name string }

func (p actionPrinter) Log(msg string)   { log.Printf("action %s: %s", p.name, msg) }
func (p actionPrinter) Warn(msg string)  { log.Printf("action %s warn: %s", p.name, msg) }
func (p actionPrinter) Error(msg string) { log.Printf("action %s error: %s", p.name, msg) }

// installRequire keeps the registry's require for the Node built-ins that are
// present (url, buffer, util) and explains the rest: npm dependencies are not
// installed in this mock, and fetch is the way out.
func (s *Server) installRequire(vm *goja.Runtime) {
	builtin, _ := goja.AssertFunction(vm.Get("require"))
	_ = vm.Set("require", func(call goja.FunctionCall) goja.Value {
		if builtin != nil {
			if v, err := builtin(goja.Undefined(), call.Arguments...); err == nil {
				return v
			}
		}
		panic(vm.NewGoError(fmt.Errorf("module %q is not available in the auth0 mock; use the global fetch", call.Argument(0).String())))
	})
}

var fetchClient = &http.Client{Timeout: 10 * time.Second}

// installFetch is a small WHATWG fetch: method, headers, string body in;
// ok, status, statusText, headers.get, text(), json() out. It runs the
// request off the loop and settles the promise back on it.
func installFetch(ctx context.Context, vm *goja.Runtime, loop *eventloop.EventLoop) {
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
		// The request runs off the loop, so the loop would otherwise see
		// nothing pending and Run would return before the response lands.
		// A timer for the run's full budget holds it open until we settle.
		hold := loop.SetTimeout(func(*goja.Runtime) {}, actionTimeout)
		go func() {
			resp, data, err := doFetch(ctx, method, target, headers, body)
			loop.RunOnLoop(func(vm *goja.Runtime) {
				loop.ClearTimeout(hold)
				if err != nil {
					_ = reject(vm.NewGoError(err))
					return
				}
				_ = resolve(fetchResponse(vm, resp, data))
			})
		}()
		return vm.ToValue(promise)
	})
}

func doFetch(ctx context.Context, method, target string, headers http.Header, body io.Reader) (*http.Response, []byte, error) {
	if _, err := url.ParseRequestURI(target); err != nil {
		return nil, nil, fmt.Errorf("fetch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header = headers
	resp, err := fetchClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	return resp, data, nil
}

func fetchResponse(vm *goja.Runtime, resp *http.Response, data []byte) *goja.Object {
	settled := func(v any, err error) goja.Value {
		p, res, rej := vm.NewPromise()
		if err != nil {
			_ = rej(vm.NewGoError(err))
		} else {
			_ = res(vm.ToValue(v))
		}
		return vm.ToValue(p)
	}
	hdr := vm.NewObject()
	_ = hdr.Set("get", func(name string) goja.Value {
		if v := resp.Header.Get(name); v != "" {
			return vm.ToValue(v)
		}
		return goja.Null()
	})
	o := vm.NewObject()
	_ = o.Set("ok", resp.StatusCode >= 200 && resp.StatusCode < 300)
	_ = o.Set("status", resp.StatusCode)
	_ = o.Set("statusText", http.StatusText(resp.StatusCode))
	_ = o.Set("headers", hdr)
	_ = o.Set("text", func() goja.Value { return settled(string(data), nil) })
	_ = o.Set("json", func() goja.Value {
		var v any
		return settled(v, json.Unmarshal(data, &v))
	})
	return o
}

// buildEvent is the post-login event, shaped like Auth0's: the same user,
// authorization, and client context the declarative block sees, plus what
// only code can use (request, transaction, secrets, organization).
func (s *Server) buildEvent(a *Action, b *ActionBinding, user *config.User, client *config.Client, orgID string, req postLoginRequest) map[string]any {
	ev := s.buildPostLoginContext(user, client, orgID)
	u := ev["user"].(map[string]any)
	u["email_verified"] = user.EmailVerified
	u["picture"] = user.Picture
	identities := make([]any, 0, len(user.Identities))
	for _, id := range user.Identities {
		identities = append(identities, map[string]any{"connection": id.Connection, "provider": id.Provider, "user_id": id.UserID, "isSocial": id.IsSocial})
	}
	u["identities"] = identities
	// An unregistered client id still names itself in the request.
	if c, ok := ev["client"].(map[string]any); ok {
		if _, has := c["client_id"]; !has {
			id := req.Query["client_id"]
			if id == "" {
				id = req.Body["client_id"]
			}
			c["client_id"], c["name"] = id, ""
		}
		c["metadata"] = map[string]any{}
	}
	if auth, ok := ev["authorization"].(map[string]any); ok {
		if _, has := auth["roles"]; !has {
			auth["roles"] = []any{}
		}
	}
	ev["connection"] = map[string]any{"id": "", "name": "", "strategy": ""}
	if len(user.Identities) > 0 {
		ev["connection"] = map[string]any{"id": "con_" + user.Identities[0].Connection, "name": user.Identities[0].Connection, "strategy": user.Identities[0].Provider}
	}
	ev["request"] = map[string]any{
		"method": req.Method, "ip": req.IP, "hostname": req.Host, "user_agent": req.UA,
		"query": req.Query, "body": req.Body, "geoip": map[string]any{},
	}
	ev["transaction"] = map[string]any{
		"protocol": req.Protocol, "requested_scopes": req.Scopes, "redirect_uri": req.RedirectURI,
		"login_hint": req.LoginHint, "ui_locales": []any{}, "locale": "en",
	}
	ev["tenant"] = map[string]any{"id": "mock"}
	ev["secrets"] = secretValues(a, b)
	ev["stats"] = map[string]any{"logins_count": 1}
	ev["authentication"] = map[string]any{"methods": []any{map[string]any{"name": "passwordless", "timestamp": time.Now().UTC().Format(time.RFC3339)}}}
	if orgID == "" {
		orgID = user.AppMetadata.TenantID()
	}
	if orgID != "" {
		s.mu.RLock()
		org := s.organizations[orgID]
		s.mu.RUnlock()
		if org != nil {
			ev["organization"] = map[string]any{"id": org.ID, "name": org.Name, "display_name": org.DisplayName, "metadata": map[string]any{}}
		}
	}
	return ev
}

// setAppMetadata and setUserMetadata persist the api.user.* calls on the
// server's user record, which is what the Management API reads back.
func (s *Server) setAppMetadata(user *config.User, key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user.AppMetadata == nil {
		user.AppMetadata = config.AppMetadata{}
	}
	if value == nil {
		delete(user.AppMetadata, key)
	} else {
		user.AppMetadata[key] = value
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

// secretBodyFields never reach an Action's event.
var secretBodyFields = map[string]bool{"code": true, "code_verifier": true, "client_secret": true, "refresh_token": true}

// requestFromToken is the post-login request for a token exchange: the
// original /authorize query when there was one, else only the token form.
func requestFromToken(r *http.Request, authorizeQuery, protocol string) postLoginRequest {
	req := postLoginRequest{Protocol: protocol, Method: r.Method, Host: r.Host, UA: r.UserAgent(), IP: clientIP(r), Query: map[string]string{}, Body: map[string]string{}}
	for k, v := range r.Form {
		if len(v) > 0 && !secretBodyFields[k] {
			req.Body[k] = v[0]
		}
	}
	if q, err := url.ParseQuery(authorizeQuery); err == nil && authorizeQuery != "" {
		for k, v := range q {
			if len(v) > 0 {
				req.Query[k] = v[0]
			}
		}
		req.Scopes = strings.Fields(q.Get("scope"))
		req.RedirectURI = q.Get("redirect_uri")
		req.LoginHint = q.Get("login_hint")
	}
	return req
}

// clientIP is the first hop behind a proxy, else the peer.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
