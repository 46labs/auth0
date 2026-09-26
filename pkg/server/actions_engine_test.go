package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// mgmt is a tiny Management API client for the tests.
type mgmt struct {
	t   *testing.T
	url string
}

func (m mgmt) do(method, path string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, m.url+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer mgmt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		m.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return resp.StatusCode, out
}

// deployBound creates, deploys, and binds a post-login action; returns its id.
func (m mgmt) deployBound(name, code string, secrets ...map[string]string) string {
	body := map[string]any{
		"name":               name,
		"code":               code,
		"runtime":            "node22",
		"supported_triggers": []map[string]string{{"id": "post-login", "version": "v3"}},
	}
	if len(secrets) > 0 {
		body["secrets"] = append([]map[string]string{}, secrets...)
	}
	st, a := m.do("POST", "/api/v2/actions/actions", body)
	if st != 201 {
		m.t.Fatalf("create %s: %d %v", name, st, a)
	}
	id := a["id"].(string)
	if st, v := m.do("POST", "/api/v2/actions/actions/"+id+"/deploy", nil); st != 200 || v["deployed"] != true {
		m.t.Fatalf("deploy: %d %v", st, v)
	}
	st, cur := m.do("GET", "/api/v2/actions/triggers/post-login/bindings", nil)
	if st != 200 {
		m.t.Fatalf("list bindings: %d", st)
	}
	refs := []map[string]any{}
	for _, b := range cur["bindings"].([]any) {
		refs = append(refs, map[string]any{"ref": map[string]string{"type": "binding_id", "value": b.(map[string]any)["id"].(string)}})
	}
	refs = append(refs, map[string]any{"ref": map[string]string{"type": "action_name", "value": name}, "display_name": name})
	if st, out := m.do("PATCH", "/api/v2/actions/triggers/post-login/bindings", map[string]any{"bindings": refs}); st != 200 {
		m.t.Fatalf("bind: %d %v", st, out)
	}
	return id
}

// login runs the auth code flow and returns the token response and status.
func login(t *testing.T, ts *httptest.Server, extraQuery string) (int, map[string]any) {
	redirectURI := "http://localhost:3000/callback"
	clientID := "test_client_actions"
	codeVerifier, codeChallenge := generatePKCE()
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&code_challenge=%s&code_challenge_method=S256%s",
		ts.URL, clientID, url.QueryEscape(redirectURI), codeChallenge, extraQuery)
	resp, err := hc.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	sessionID := regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(string(body))[1]
	resp2, err := hc.PostForm(ts.URL+"/authorize", url.Values{"session_id": {sessionID}, "phone": {"+14155551234"}, "code": {"123456"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	loc, _ := url.Parse(resp2.Header.Get("Location"))
	resp3, err := hc.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"redirect_uri": {redirectURI}, "code_verifier": {codeVerifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp3.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp3.Body).Decode(&out)
	return resp3.StatusCode, out
}

func claims(t *testing.T, token any) jwt.MapClaims {
	s, _ := token.(string)
	parsed, _, err := jwt.NewParser().ParseUnverified(s, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return parsed.Claims.(jwt.MapClaims)
}

func TestActions_ManagementRoundTrip(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}

	st, trig := m.do("GET", "/api/v2/actions/triggers", nil)
	if st != 200 || len(trig["triggers"].([]any)) == 0 {
		t.Fatalf("triggers: %d %v", st, trig)
	}
	st, a := m.do("POST", "/api/v2/actions/actions", map[string]any{
		"name": "one", "code": "exports.onExecutePostLogin = async () => {};",
		"supported_triggers": []map[string]string{{"id": "post-login", "version": "v3"}},
		"secrets":            []map[string]string{{"name": "TOKEN", "value": "s3cret"}},
	})
	if st != 201 || a["status"] != "built" || a["deployed_version"] != nil {
		t.Fatalf("create: %d %v", st, a)
	}
	if secs := a["secrets"].([]any); len(secs) != 1 || secs[0].(map[string]any)["value"] != nil {
		t.Fatalf("secret value must not be returned: %v", a["secrets"])
	}
	id := a["id"].(string)
	if st, _ := m.do("POST", "/api/v2/actions/actions", map[string]any{"name": "one"}); st != 409 {
		t.Fatalf("duplicate name should be 409, got %d", st)
	}
	st, list := m.do("GET", "/api/v2/actions/actions?actionName=one", nil)
	if st != 200 || list["total"].(float64) != 1 {
		t.Fatalf("list by name: %d %v", st, list)
	}
	st, list = m.do("GET", "/api/v2/actions/actions?triggerId=credentials-exchange", nil)
	if st != 200 || list["total"].(float64) != 0 {
		t.Fatalf("list by other trigger: %d %v", st, list)
	}
	st, p := m.do("PATCH", "/api/v2/actions/actions/"+id, map[string]any{"code": "exports.onExecutePostLogin = async () => { };"})
	if st != 200 || p["all_changes_deployed"] != false {
		t.Fatalf("patch: %d %v", st, p)
	}
	st, v := m.do("POST", "/api/v2/actions/actions/"+id+"/deploy", nil)
	if st != 200 || v["number"].(float64) != 1 || v["deployed"] != true {
		t.Fatalf("deploy: %d %v", st, v)
	}
	st, a = m.do("GET", "/api/v2/actions/actions/"+id, nil)
	if st != 200 || a["all_changes_deployed"] != true || a["deployed_version"] == nil {
		t.Fatalf("after deploy: %d %v", st, a)
	}
	st, b := m.do("PATCH", "/api/v2/actions/triggers/post-login/bindings", map[string]any{"bindings": []map[string]any{{"ref": map[string]string{"type": "action_id", "value": id}, "display_name": "One"}}})
	if st != 200 || len(b["bindings"].([]any)) != 1 {
		t.Fatalf("bind: %d %v", st, b)
	}
	if st, _ := m.do("DELETE", "/api/v2/actions/actions/"+id, nil); st != 409 {
		t.Fatalf("delete while bound should be 409, got %d", st)
	}
	if st, _ := m.do("PATCH", "/api/v2/actions/triggers/post-login/bindings", map[string]any{"bindings": []any{}}); st != 200 {
		t.Fatalf("unbind: %d", st)
	}
	if st, _ := m.do("DELETE", "/api/v2/actions/actions/"+id, nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if st, _ := m.do("GET", "/api/v2/actions/actions/"+id, nil); st != 404 {
		t.Fatalf("gone: %d", st)
	}
	if st, _ := m.do("PATCH", "/api/v2/actions/triggers/nope/bindings", map[string]any{"bindings": []any{}}); st != 400 {
		t.Fatalf("unknown trigger should be 400, got %d", st)
	}
}

func TestActions_PostLoginSetsClaimsAndSeesEvent(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("claims", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/phone", event.user.phone_number);
		  api.accessToken.setCustomClaim("https://mock/device", event.request.query.device_id);
		  api.accessToken.setCustomClaim("https://mock/secret", event.secrets.TOKEN);
		  api.accessToken.setCustomClaim("https://mock/proto", event.transaction.protocol);
		  api.idToken.setCustomClaim("https://mock/client", event.client.client_id);
		  api.user.setAppMetadata("paired", true);
		};`, map[string]string{"name": "TOKEN", "value": "s3cret"})

	st, tok := login(t, ts, "&device_id=dev-42")
	if st != 200 {
		t.Fatalf("token: %d %v", st, tok)
	}
	ac := claims(t, tok["access_token"])
	if ac["https://mock/phone"] != "+14155551234" || ac["https://mock/device"] != "dev-42" || ac["https://mock/secret"] != "s3cret" || ac["https://mock/proto"] != "oidc-basic-profile" {
		t.Fatalf("access claims: %v", ac)
	}
	if ic := claims(t, tok["id_token"]); ic["https://mock/client"] != "test_client_actions" {
		t.Fatalf("id claims: %v", ic)
	}
	// Metadata set by the action is visible to the next run.
	m.deployBound("reads-meta", `
		exports.onExecutePostLogin = async (event, api) => {
		  api.accessToken.setCustomClaim("https://mock/paired", event.user.app_metadata.paired === true);
		};`)
	st, tok = login(t, ts, "")
	if st != 200 || claims(t, tok["access_token"])["https://mock/paired"] != true {
		t.Fatalf("metadata round trip: %d %v", st, tok)
	}
}

func TestActions_DenyStopsTheLogin(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("gate", `
		exports.onExecutePostLogin = async (event, api) => {
		  if (!event.request.query.approved) api.access.deny("a guardian must approve this device");
		};`)
	st, body := login(t, ts, "")
	if st != 403 || body["error"] != "access_denied" || !strings.Contains(body["error_description"].(string), "guardian") {
		t.Fatalf("deny: %d %v", st, body)
	}
	if st, tok := login(t, ts, "&approved=1"); st != 200 || tok["access_token"] == nil {
		t.Fatalf("approved login: %d %v", st, tok)
	}
}

func TestActions_FetchReachesAWebhook(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	var seen struct {
		method, auth, body string
	}
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen.method, seen.auth, seen.body = r.Method, r.Header.Get("Authorization"), string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"deny","reason":"not approved yet"}`))
	}))
	defer hook.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("webhook", `
		exports.onExecutePostLogin = async (event, api) => {
		  const res = await fetch(event.secrets.HOOK, {
		    method: "POST",
		    headers: { "Authorization": "Bearer " + event.secrets.TOKEN, "Content-Type": "application/json" },
		    body: JSON.stringify({ user_id: event.user.user_id, device_id: event.request.query.device_id }),
		  });
		  if (!res.ok) { api.access.deny("approval service unavailable"); return; }
		  const d = await res.json();
		  if (d.decision === "deny") api.access.deny(d.reason);
		};`, map[string]string{"name": "HOOK", "value": hook.URL + "/hook"}, map[string]string{"name": "TOKEN", "value": "hook-secret"})
	st, body := login(t, ts, "&device_id=phone-1")
	if st != 403 || body["error_description"] != "not approved yet" {
		t.Fatalf("webhook deny: %d %v", st, body)
	}
	if seen.method != "POST" || seen.auth != "Bearer hook-secret" || !strings.Contains(seen.body, `"device_id":"phone-1"`) || !strings.Contains(seen.body, `"user_id":"test_user_1"`) {
		t.Fatalf("webhook saw %+v", seen)
	}
}

func TestActions_UndeployedAndThrowing(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	// Bound but never deployed: skipped.
	st, a := m.do("POST", "/api/v2/actions/actions", map[string]any{"name": "draft", "code": `exports.onExecutePostLogin = async (e, api) => { api.access.deny("draft ran"); };`, "supported_triggers": []map[string]string{{"id": "post-login", "version": "v3"}}})
	if st != 201 {
		t.Fatal(st)
	}
	if st, _ := m.do("PATCH", "/api/v2/actions/triggers/post-login/bindings", map[string]any{"bindings": []map[string]any{{"ref": map[string]string{"type": "action_id", "value": a["id"].(string)}}}}); st != 200 {
		t.Fatal(st)
	}
	if st, _ := login(t, ts, ""); st != 200 {
		t.Fatalf("undeployed action must not run, got %d", st)
	}
	// A throwing action fails the login rather than issuing tokens.
	m.deployBound("boom", `exports.onExecutePostLogin = async () => { throw new Error("kaboom"); };`)
	st, body := login(t, ts, "")
	if st != 403 || !strings.Contains(fmt.Sprint(body["error_description"]), "kaboom") {
		t.Fatalf("throwing action: %d %v", st, body)
	}
}
