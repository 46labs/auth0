package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
	"github.com/golang-jwt/jwt/v5"

	"github.com/46labs/auth0/pkg/config"
)

// receivedPost is one delivery a test receiver accepted.
type receivedPost struct {
	Header http.Header
	Body   []byte
}

// logReceiver is a webhook endpoint that records deliveries. fail answers the
// first n requests with 500.
type logReceiver struct {
	mu    sync.Mutex
	posts []receivedPost
	fail  int
	ts    *httptest.Server
}

// newLogReceiver serves TLS, as Auth0 requires an https endpoint, and makes
// srv's delivery client trust it.
func newLogReceiver(t *testing.T, srv *Server, fail int) *logReceiver {
	t.Helper()
	rcv := &logReceiver{fail: fail}
	rcv.ts = httptest.NewTLSServer(http.HandlerFunc(rcv.serve))
	t.Cleanup(rcv.ts.Close)
	trustTestTLS(srv)
	return rcv
}

// streamTo creates a stream delivering to a new receiver.
func streamTo(t *testing.T, srv *Server, baseURL, format string, filters ...string) *logReceiver {
	t.Helper()
	rcv := newLogReceiver(t, srv, 0)
	if err := newMgmt(t, baseURL).LogStream.Create(context.Background(), httpStream("s", rcv.ts.URL, format, filters...)); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	return rcv
}

// trustTestTLS makes srv's delivery client trust httptest's TLS certificate,
// which every httptest TLS server shares.
func trustTestTLS(srv *Server) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	srv.logDeliveryClient.Transport = ts.Client().Transport
}

func (rcv *logReceiver) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	rcv.posts = append(rcv.posts, receivedPost{Header: r.Header, Body: body})
	if rcv.fail > 0 {
		rcv.fail--
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (rcv *logReceiver) received() []receivedPost {
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	return append([]receivedPost(nil), rcv.posts...)
}

// records decodes every accepted delivery's records, in arrival order.
func (rcv *logReceiver) records(t *testing.T, format string) []logRecord {
	t.Helper()
	var out []logRecord
	for _, p := range rcv.received() {
		out = append(out, decodeBatch(t, format, p.Body)...)
	}
	return out
}

func decodeBatch(t *testing.T, format string, body []byte) []logRecord {
	t.Helper()
	var recs []logRecord
	switch format {
	case "JSONARRAY":
		if err := json.Unmarshal(body, &recs); err != nil {
			t.Fatalf("decode array batch: %v (%s)", err, body)
		}
	case "JSONOBJECT":
		var wrapped struct {
			Logs []logRecord `json:"logs"`
		}
		if err := json.Unmarshal(body, &wrapped); err != nil {
			t.Fatalf("decode object batch: %v (%s)", err, body)
		}
		recs = wrapped.Logs
	default:
		sc := bufio.NewScanner(bytes.NewReader(body))
		for sc.Scan() {
			var r logRecord
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatalf("decode line: %v (%s)", err, sc.Bytes())
			}
			recs = append(recs, r)
		}
	}
	return recs
}

func typesOf(recs []logRecord) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Data["type"].(string))
	}
	return out
}

func newMgmt(t *testing.T, baseURL string, opts ...management.Option) *management.Management {
	t.Helper()
	m, err := management.New(baseURL, append([]management.Option{
		management.WithStaticToken("mock_token"),
		management.WithInsecure(),
	}, opts...)...)
	if err != nil {
		t.Fatalf("management client: %v", err)
	}
	return m
}

func httpStream(name, endpoint, format string, filters ...string) *management.LogStream {
	ls := &management.LogStream{
		Name: auth0.String(name),
		Type: auth0.String(management.LogStreamTypeHTTP),
		Sink: &management.LogStreamSinkHTTP{
			Endpoint:      auth0.String(endpoint),
			Authorization: auth0.String("Bearer stream-token"),
			ContentFormat: auth0.String(format),
			ContentType:   auth0.String("application/json"),
		},
	}
	if len(filters) > 0 {
		fs := make([]map[string]string, 0, len(filters))
		for _, f := range filters {
			fs = append(fs, map[string]string{"type": "category", "name": f})
		}
		ls.Filters = &fs
	}
	return ls
}

func withPII(ls *management.LogStream, method, algorithm string, fields ...string) *management.LogStream {
	ls.PIIConfig = &management.LogStreamPiiConfig{
		LogFields: &fields, Method: auth0.String(method), Algorithm: auth0.String(algorithm),
	}
	return ls
}

func withStart(ls *management.LogStream, start string) *management.LogStream {
	ls.StartFrom = auth0.String(start)
	return ls
}

func statusOf(err error) int {
	var mErr management.Error
	if errors.As(err, &mErr) {
		return mErr.Status()
	}
	return 0
}

func TestLogStreamCRUDThroughSDK(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := newMgmt(t, ts.URL)
	ctx := context.Background()

	ls := httpStream("pee-audit", "https://pee.example.test/api/v1/auth0/log-stream", "JSONARRAY", "auth.login.success")
	if err := m.LogStream.Create(ctx, ls); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(ls.GetID(), "lst_") || ls.GetStatus() != "active" {
		t.Fatalf("created stream id=%q status=%q", ls.GetID(), ls.GetStatus())
	}

	got, err := m.LogStream.Read(ctx, ls.GetID())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sink, ok := got.Sink.(*management.LogStreamSinkHTTP)
	if !ok {
		t.Fatalf("sink decoded as %T, want *LogStreamSinkHTTP", got.Sink)
	}
	if sink.GetEndpoint() != "https://pee.example.test/api/v1/auth0/log-stream" ||
		sink.GetAuthorization() != "Bearer stream-token" || sink.GetContentFormat() != "JSONARRAY" {
		t.Fatalf("sink = %+v", sink)
	}
	if got.Filters == nil || len(*got.Filters) != 1 || (*got.Filters)[0]["name"] != "auth.login.success" {
		t.Fatalf("filters = %v", got.Filters)
	}

	list, err := m.LogStream.List(ctx)
	if err != nil || len(list) != 1 || list[0].GetID() != ls.GetID() {
		t.Fatalf("list = %v, %v", list, err)
	}

	// A sink PATCH naming one field keeps the others.
	filters := []map[string]string{{"type": "category", "name": "auth.login.fail"}}
	if err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{
		Filters: &filters,
		Sink:    &management.LogStreamSinkHTTP{Endpoint: auth0.String("https://moved.example.test/hook")},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = m.LogStream.Read(ctx, ls.GetID())
	if err != nil {
		t.Fatalf("read after update: %v", err)
	}
	sink = got.Sink.(*management.LogStreamSinkHTTP)
	if sink.GetEndpoint() != "https://moved.example.test/hook" || sink.GetAuthorization() != "Bearer stream-token" {
		t.Fatalf("sink after partial update = %+v", sink)
	}
	if (*got.Filters)[0]["name"] != "auth.login.fail" {
		t.Fatalf("filters after update = %v", *got.Filters)
	}

	if err := m.LogStream.Delete(ctx, ls.GetID()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := m.LogStream.Read(ctx, ls.GetID()); statusOf(err) != http.StatusNotFound {
		t.Fatalf("read after delete: %v, want 404", err)
	}
	// Auth0's recorded traffic answers a repeated delete with 204.
	if err := m.LogStream.Delete(ctx, ls.GetID()); err != nil {
		t.Fatalf("second delete: %v, want success", err)
	}
}

func TestLogStreamRefusesWhatAuth0Refuses(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := newMgmt(t, ts.URL)
	ctx := context.Background()

	cases := []struct {
		name string
		ls   *management.LogStream
	}{
		{"unknown type", &management.LogStream{Type: auth0.String("kafka"), Sink: map[string]any{}}},
		{"no sink", &management.LogStream{Type: auth0.String("http")}},
		{"no endpoint", &management.LogStream{Type: auth0.String("http"), Sink: &management.LogStreamSinkHTTP{ContentFormat: auth0.String("JSONARRAY")}}},
		{"bad format", httpStream("s", "https://x.example.test", "XML")},
		{"bad filter", httpStream("s", "https://x.example.test", "JSONARRAY", "auth.login.maybe")},
		{"security filter", httpStream("s", "https://x.example.test", "JSONARRAY", "security")},
		{"bad name", httpStream("-leading", "https://x.example.test", "JSONARRAY")},
		{"http endpoint", httpStream("s", "http://x.example.test/logs", "JSONARRAY")},
		{"status on create", func() *management.LogStream {
			ls := httpStream("s", "https://x.example.test", "JSONARRAY")
			ls.Status = auth0.String("paused")
			return ls
		}()},
		{"datadog missing region", &management.LogStream{Type: auth0.String("datadog"), Sink: &management.LogStreamSinkDatadog{APIKey: auth0.String("k")}}},
		{"datadog bad region", &management.LogStream{Type: auth0.String("datadog"), Sink: &management.LogStreamSinkDatadog{APIKey: auth0.String("k"), Region: auth0.String("ap")}}},
		{"eventbridge bad account", &management.LogStream{Type: auth0.String("eventbridge"), Sink: &management.LogStreamSinkAmazonEventBridge{AccountID: auth0.String("123"), Region: auth0.String("us-west-2")}}},
		{"eventgrid bad subscription", &management.LogStream{Type: auth0.String("eventgrid"), Sink: &management.LogStreamSinkAzureEventGrid{
			SubscriptionID: auth0.String("nope"), ResourceGroup: auth0.String("rg"), Region: auth0.String("westus"),
		}}},
		{"splunk missing secure", &management.LogStream{Type: auth0.String("splunk"), Sink: &management.LogStreamSinkSplunk{
			Domain: auth0.String("d"), Token: auth0.String("t"), Port: auth0.String("8088"),
		}}},
		{"mixpanel password with colon", &management.LogStream{Type: auth0.String("mixpanel"), Sink: &management.LogStreamSinkMixpanel{
			Region: auth0.String("us"), ProjectID: auth0.String("1"), ServiceAccountUsername: auth0.String("u"), ServiceAccountPassword: auth0.String("a:b"),
		}}},
		{"sink field of another type", &management.LogStream{Type: auth0.String("sumo"), Sink: &management.LogStreamSinkSegment{WriteKey: auth0.String("k")}}},
		{"pii field outside enum", withPII(httpStream("p", "https://x.example.test", "JSONARRAY"), "hash", "xxhash", "ssn")},
		{"pii method outside enum", withPII(httpStream("p", "https://x.example.test", "JSONARRAY"), "redact", "xxhash", "email")},
		{"pii no fields", withPII(httpStream("p", "https://x.example.test", "JSONARRAY"), "hash", "xxhash")},
		{"startFrom not a date", withStart(httpStream("p", "https://x.example.test", "JSONARRAY"), "not-a-date")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := m.LogStream.Create(ctx, tc.ls); statusOf(err) != http.StatusBadRequest {
				t.Fatalf("create: %v, want 400", err)
			}
		})
	}
	list, err := m.LogStream.List(ctx)
	if err != nil || len(list) != 0 {
		t.Fatalf("refused creates left streams behind: %v, %v", list, err)
	}

	ls := httpStream("ok", "https://x.example.test", "JSONARRAY")
	if err := m.LogStream.Create(ctx, ls); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Run("type is not updatable", func(t *testing.T) {
		err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{Type: auth0.String("datadog")})
		if statusOf(err) != http.StatusBadRequest {
			t.Fatalf("update type: %v, want 400", err)
		}
	})
	t.Run("sink patch must name the endpoint", func(t *testing.T) {
		err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{
			Sink: &management.LogStreamSinkHTTP{Authorization: auth0.String("Bearer new")},
		})
		if statusOf(err) != http.StatusBadRequest {
			t.Fatalf("update: %v, want 400", err)
		}
	})
	t.Run("refused update changes nothing", func(t *testing.T) {
		err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{
			Name: auth0.String("renamed"),
			Sink: &management.LogStreamSinkHTTP{Endpoint: auth0.String("https://x.example.test"), ContentFormat: auth0.String("XML")},
		})
		if statusOf(err) != http.StatusBadRequest {
			t.Fatalf("update: %v, want 400", err)
		}
		got, err := m.LogStream.Read(ctx, ls.GetID())
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if got.GetName() != "ok" || got.Sink.(*management.LogStreamSinkHTTP).GetContentFormat() != "JSONARRAY" {
			t.Fatalf("stream after refused update = %+v", got)
		}
	})
}

// Each type round-trips through the SDK as go-auth0's recorded Auth0 traffic
// shows: priority streams carry the security filter whatever was asked,
// pii_config is stored and replaced, the EventBridge partner source is
// generated, and the Mixpanel password is masked.
func TestLogStreamTypesMatchRecordedAuth0(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := newMgmt(t, ts.URL)
	ctx := context.Background()

	pii := func(ls *management.LogStream) *management.LogStream {
		return withStart(withPII(ls, "mask", "xxhash", "first_name"), "2026-10-13T00:00:00Z")
	}
	cases := []struct {
		name     string
		ls       *management.LogStream
		priority bool
		check    func(t *testing.T, got *management.LogStream)
	}{
		{"http", pii(httpStream("h", "https://x.example.test", "JSONLINES")), false, func(t *testing.T, got *management.LogStream) {
			if got.Sink.(*management.LogStreamSinkHTTP).GetAuthorization() != "Bearer stream-token" {
				t.Fatalf("http sink = %+v", got.Sink)
			}
		}},
		{"eventbridge", pii(&management.LogStream{Type: auth0.String("eventbridge"), Sink: &management.LogStreamSinkAmazonEventBridge{
			AccountID: auth0.String("999999999999"), Region: auth0.String("us-west-2"),
		}}), true, func(t *testing.T, got *management.LogStream) {
			src := got.Sink.(*management.LogStreamSinkAmazonEventBridge).GetPartnerEventSource()
			if !strings.HasPrefix(src, "aws.partner/auth0.com/") || !strings.HasSuffix(src, "/auth0.logs") {
				t.Fatalf("partner event source = %q", src)
			}
		}},
		{"eventgrid", pii(&management.LogStream{Type: auth0.String("eventgrid"), Sink: &management.LogStreamSinkAzureEventGrid{
			SubscriptionID: auth0.String("b69a6835-57c7-4d53-b0d5-1c6ae580b6d5"), ResourceGroup: auth0.String("rg"), Region: auth0.String("northeurope"),
		}}), true, func(t *testing.T, got *management.LogStream) {
			if got.Sink.(*management.LogStreamSinkAzureEventGrid).GetPartnerTopic() == "" {
				t.Fatal("no partner topic")
			}
		}},
		{"datadog", pii(&management.LogStream{Type: auth0.String("datadog"), Sink: &management.LogStreamSinkDatadog{
			APIKey: auth0.String("121233123455"), Region: auth0.String("us"),
		}}), true, func(t *testing.T, got *management.LogStream) {
			if got.Sink.(*management.LogStreamSinkDatadog).GetAPIKey() != "121233123455" {
				t.Fatalf("datadog sink = %+v", got.Sink)
			}
		}},
		{"splunk", pii(&management.LogStream{Type: auth0.String("splunk"), Sink: &management.LogStreamSinkSplunk{
			Domain: auth0.String("demo.splunk.com"), Token: auth0.String("t"), Port: auth0.String("8080"), Secure: auth0.Bool(true),
		}}), true, func(t *testing.T, got *management.LogStream) {
			if !got.Sink.(*management.LogStreamSinkSplunk).GetSecure() {
				t.Fatalf("splunk sink = %+v", got.Sink)
			}
		}},
		{"sumo", pii(&management.LogStream{Type: auth0.String("sumo"), Sink: &management.LogStreamSinkSumo{
			SourceAddress: auth0.String("https://example.com"),
		}}), true, nil},
		{"segment", pii(&management.LogStream{Type: auth0.String("segment"), Sink: &management.LogStreamSinkSegment{
			WriteKey: auth0.String("121233123455"),
		}}), true, nil},
		{"mixpanel", pii(&management.LogStream{Type: auth0.String("mixpanel"), Sink: &management.LogStreamSinkMixpanel{
			Region: auth0.String("us"), ProjectID: auth0.String("123456789"),
			ServiceAccountUsername: auth0.String("svc.123abc.mp-service-account"), ServiceAccountPassword: auth0.String("secret"),
		}}), false, func(t *testing.T, got *management.LogStream) {
			if p := got.Sink.(*management.LogStreamSinkMixpanel).GetServiceAccountPassword(); p != "********" {
				t.Fatalf("mixpanel password = %q, want masked", p)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.ls.Name = auth0.String("Test-" + tc.name)
			tc.ls.IsPriority = auth0.Bool(tc.priority)
			if err := m.LogStream.Create(ctx, tc.ls); err != nil {
				t.Fatalf("create: %v", err)
			}

			// The update every recording sends: new filters and pii_config.
			filters := []map[string]string{{"name": "auth.login.fail", "type": "category"}}
			if err := m.LogStream.Update(ctx, tc.ls.GetID(), withPII(&management.LogStream{Filters: &filters}, "hash", "xxhash", "last_name")); err != nil {
				t.Fatalf("update: %v", err)
			}
			got, err := m.LogStream.Read(ctx, tc.ls.GetID())
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			// startFrom is accepted on create and not returned.
			if got.GetType() != tc.name || got.GetStatus() != "active" || got.GetIsPriority() != tc.priority || got.StartFrom != nil {
				t.Fatalf("stream = %+v", got)
			}
			if p := got.PIIConfig; p == nil || p.GetMethod() != "hash" || len(p.GetLogFields()) != 1 || p.GetLogFields()[0] != "last_name" {
				t.Fatalf("pii_config = %+v", got.PIIConfig)
			}
			wantFilter := "auth.login.fail"
			if tc.priority {
				wantFilter = "security"
			}
			if got.Filters == nil || len(*got.Filters) != 1 || (*got.Filters)[0]["name"] != wantFilter {
				t.Fatalf("filters = %v, want [%s]", got.Filters, wantFilter)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}

	t.Run("eventbridge sink is not updatable", func(t *testing.T) {
		ls := &management.LogStream{Type: auth0.String("eventbridge"), Sink: &management.LogStreamSinkAmazonEventBridge{
			AccountID: auth0.String("999999999999"), Region: auth0.String("us-west-2"),
		}}
		if err := m.LogStream.Create(ctx, ls); err != nil {
			t.Fatalf("create: %v", err)
		}
		err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{Sink: &management.LogStreamSinkAmazonEventBridge{
			AccountID: auth0.String("111111111111"), Region: auth0.String("us-east-1"),
		}})
		if statusOf(err) != http.StatusBadRequest {
			t.Fatalf("update sink: %v, want 400", err)
		}
	})

	t.Run("mixpanel patch without password keeps it", func(t *testing.T) {
		ls := &management.LogStream{Type: auth0.String("mixpanel"), Sink: &management.LogStreamSinkMixpanel{
			Region: auth0.String("us"), ProjectID: auth0.String("1"), ServiceAccountUsername: auth0.String("u"), ServiceAccountPassword: auth0.String("p"),
		}}
		if err := m.LogStream.Create(ctx, ls); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{Sink: &management.LogStreamSinkMixpanel{
			Region: auth0.String("eu"), ProjectID: auth0.String("2"), ServiceAccountUsername: auth0.String("u2"),
		}}); err != nil {
			t.Fatalf("update: %v", err)
		}
		if err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{Sink: &management.LogStreamSinkMixpanel{
			Region: auth0.String("eu"), ProjectID: auth0.String("2"),
		}}); statusOf(err) != http.StatusBadRequest {
			t.Fatalf("patch without username: %v, want 400", err)
		}
	})
}

// failLogin drives /authorize with a wrong one-time code. Raw HTTP: OIDC
// browser flow.
func failLogin(t *testing.T, baseURL, identifier, orgID string) {
	t.Helper()
	client := noRedirectClient()
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"test_client"},
		"redirect_uri":  {testRedirectURI},
		"organization":  {orgID},
	}
	resp, err := client.Get(baseURL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	sid := sessionIDRe.FindStringSubmatch(string(body))
	if len(sid) < 2 {
		t.Fatal("no session_id in login page")
	}
	resp, err = client.PostForm(baseURL+"/authorize", url.Values{
		"session_id": {sid[1]},
		"identifier": {identifier},
		"code":       {"000000"},
	})
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong code answered %d", resp.StatusCode)
	}
}

func TestLoginEventsDeliveredToMatchingStreams(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	m := newMgmt(t, ts.URL)
	ctx := context.Background()

	all := newLogReceiver(t, srv, 0)
	failures := newLogReceiver(t, srv, 0)
	paused := newLogReceiver(t, srv, 0)
	for _, ls := range []*management.LogStream{
		httpStream("all", all.ts.URL, "JSONARRAY"),
		httpStream("failures", failures.ts.URL, "JSONLINES", "auth.login.fail"),
		httpStream("paused", paused.ts.URL, "JSONOBJECT"),
	} {
		if err := m.LogStream.Create(ctx, ls); err != nil {
			t.Fatalf("create %s: %v", ls.GetName(), err)
		}
		if ls.GetName() == "paused" {
			if err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{Status: auth0.String("paused")}); err != nil {
				t.Fatalf("pause: %v", err)
			}
		}
	}

	if _, status, msg := loginToOrg(t, ts.URL, "+14155551234", "org_test", "openid"); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, msg)
	}
	failLogin(t, ts.URL, "+14155551234", "org_test")
	srv.logDeliveries.Wait()

	recs := all.records(t, "JSONARRAY")
	if got := typesOf(recs); len(got) != 2 || !slices.Contains(got, "s") || !slices.Contains(got, "f") {
		t.Fatalf("unfiltered stream got %v, want s and f", got)
	}
	for _, r := range recs {
		d := r.Data
		if r.LogID == "" || d["log_id"] != r.LogID || d["date"] == nil {
			t.Fatalf("record missing ids: %+v", r)
		}
		if d["organization_id"] != "org_test" || d["organization_name"] != "test-org" || d["user_id"] != "test_user_1" {
			t.Fatalf("record %s attribution = %+v", d["type"], d)
		}
		if d["connection"] != "sms" || d["connection_id"] != "con_sms" || d["ip"] == "" {
			t.Fatalf("record %s connection/ip = %+v", d["type"], d)
		}
		// Required by Auth0's s and f schemas.
		if d["strategy"] != "sms" || d["strategy_type"] != "passwordless" || d["hostname"] == "" {
			t.Fatalf("record %s strategy/hostname = %+v", d["type"], d)
		}
		if _, ok := d["client_name"].(string); !ok {
			t.Fatalf("record %s has no client_name: %+v", d["type"], d)
		}
		errDetail, hasErr := d["details"].(map[string]any)["error"].(map[string]any)
		if (d["type"] == "f") != hasErr || (hasErr && errDetail["message"] != d["description"]) {
			t.Fatalf("record %s details = %+v", d["type"], d["details"])
		}
	}
	for _, p := range all.received() {
		if p.Header.Get("Authorization") != "Bearer stream-token" || p.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("delivery headers = %v", p.Header)
		}
	}

	if got := typesOf(failures.records(t, "JSONLINES")); len(got) != 1 || got[0] != "f" {
		t.Fatalf("failure-filtered stream got %v, want [f]", got)
	}
	if got := paused.received(); len(got) != 0 {
		t.Fatalf("paused stream got %d deliveries", len(got))
	}
}

func TestLoginRefusedByOrgIsFailedLogin(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	m := newMgmt(t, ts.URL)
	ctx := context.Background()

	rcv := streamTo(t, srv, ts.URL, "JSONOBJECT")
	other := &management.Organization{Name: auth0.String("other-org")}
	if err := m.Organization.Create(ctx, other); err != nil {
		t.Fatalf("create org: %v", err)
	}

	if _, status, _ := loginToOrg(t, ts.URL, "+14155551234", other.GetID(), "openid"); status == http.StatusOK {
		t.Fatal("non-member login succeeded")
	}
	srv.logDeliveries.Wait()

	recs := rcv.records(t, "JSONOBJECT")
	if len(recs) != 1 || recs[0].Data["type"] != "f" || recs[0].Data["organization_id"] != other.GetID() {
		t.Fatalf("records = %+v", recs)
	}
}

func TestLogDeliveryRetriesNon2xx(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.logRetryBackoff = 0
	m := newMgmt(t, ts.URL)

	rcv := newLogReceiver(t, srv, 2)
	if err := m.LogStream.Create(context.Background(), httpStream("s", rcv.ts.URL, "JSONARRAY")); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	if _, status, msg := loginToOrg(t, ts.URL, "+14155551234", "org_test", "openid"); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, msg)
	}
	srv.logDeliveries.Wait()

	posts := rcv.received()
	if len(posts) != 3 {
		t.Fatalf("attempts = %d, want 3 (two refused, one accepted)", len(posts))
	}
	if !bytes.Equal(posts[0].Body, posts[2].Body) {
		t.Fatal("retry sent a different batch")
	}
}

func TestExchangeEventsCarryActorAndNativeOrgOnly(t *testing.T) {
	cases := []struct {
		name     string
		orgClaim string
		wantOrg  bool
	}{
		{"native org_id", "", true},
		{"namespaced org claim", "https://auth.example.test/org_id", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := exchangeServer(t, &config.TokenExchangeAction{
				RequireClaim: exNS + "platform",
				Actor:        true,
				OrgClaim:     tc.orgClaim,
			})
			srv.logRetryBackoff = 0
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()

			rcv := streamTo(t, srv, ts.URL, "JSONARRAY", "auth.token_exchange.success", "auth.token_exchange.fail")

			ok := doExchange(t, srv, srv.signSubject(t, jwt.MapClaims{"sub": "auth0|admin", exNS + "platform": "admin"}), "org_2")
			if ok.Code != http.StatusOK {
				t.Fatalf("exchange: %d %s", ok.Code, ok.Body)
			}
			denied := doExchange(t, srv, srv.signSubject(t, jwt.MapClaims{"sub": "auth0|user"}), "org_2")
			if denied.Code != http.StatusForbidden {
				t.Fatalf("denied exchange: %d", denied.Code)
			}
			srv.logDeliveries.Wait()

			byType := map[string]map[string]any{}
			for _, r := range rcv.records(t, "JSONARRAY") {
				byType[r.Data["type"].(string)] = r.Data
			}
			success, failure := byType["secte"], byType["fecte"]
			if success == nil || failure == nil {
				t.Fatalf("got %v, want secte and fecte", byType)
			}
			details := success["details"].(map[string]any)
			if actor, _ := details["actor"].(map[string]any); actor["sub"] != "auth0|admin" {
				t.Fatalf("secte details = %v", details)
			}
			if details["subject_token_type"] != exSubjectType || success["user_id"] != "auth0|admin" {
				t.Fatalf("secte = %v", success)
			}
			if _, has := success["organization_id"]; has != tc.wantOrg {
				t.Fatalf("secte organization_id present=%v, want %v", has, tc.wantOrg)
			}
			for _, d := range []map[string]any{success, failure} {
				if _, ok := d["client_name"].(string); !ok || d["hostname"] == nil {
					t.Fatalf("%s missing required fields: %v", d["type"], d)
				}
			}
			if failure["user_id"] != "auth0|user" || failure["description"] != "subject not permitted to exchange" {
				t.Fatalf("fecte = %v", failure)
			}
			if _, has := failure["details"].(map[string]any)["actor"]; has {
				t.Fatal("fecte carries an actor")
			}
		})
	}
}

func TestLogDeliveryTrustsConfiguredCA(t *testing.T) {
	var hits int
	var mu sync.Mutex
	tlsRcv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer tlsRcv.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	srv := &Server{
		cfg:               &config.Config{LogStreamCAFile: caFile},
		logDeliveryClient: logDeliveryClient(),
		logStreams: map[string]*logStream{"lst_1": {
			ID: "lst_1", Type: "http", Status: "active",
			Sink: map[string]any{"httpEndpoint": tlsRcv.URL, "httpContentFormat": "JSONARRAY", "httpContentType": "application/json"},
		}},
	}
	deliver := func(t *testing.T, want int) {
		t.Helper()
		mu.Lock()
		hits = 0
		mu.Unlock()
		srv.emitLog(map[string]any{"type": "s"})
		srv.logDeliveries.Wait()
		mu.Lock()
		defer mu.Unlock()
		if hits != want {
			t.Fatalf("hits = %d, want %d", hits, want)
		}
	}

	// The CA is read per delivery: absent at first, as when the Secret holding
	// it is issued after the mock starts, then present.
	deliver(t, 0)
	if err := os.WriteFile(caFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	deliver(t, 0)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsRcv.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	deliver(t, 1)

	srv.cfg.LogStreamCAFile = ""
	deliver(t, 0)

	srv.cfg.LogStreamCAFile = caFile
	client, err := srv.deliveryClient()
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := client.Transport.(*http.Transport); !ok || tr.Proxy == nil || client.CheckRedirect == nil {
		t.Fatal("CA client dropped the default transport's proxy settings or the redirect policy")
	}
}

func TestLogStreamsUnderConcurrentLoginsAndUpdates(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.logRetryBackoff = 0
	m := newMgmt(t, ts.URL)
	ctx := context.Background()

	rcv := newLogReceiver(t, srv, 0)
	ls := httpStream("s", rcv.ts.URL, "JSONARRAY")
	if err := m.LogStream.Create(ctx, ls); err != nil {
		t.Fatalf("create stream: %v", err)
	}

	const logins = 8
	var wg sync.WaitGroup
	for range logins {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, status, msg := loginToOrg(t, ts.URL, "+14155551234", "org_test", "openid"); status != http.StatusOK {
				t.Errorf("login: %d %s", status, msg)
			}
		}()
		go func() {
			defer wg.Done()
			if err := m.LogStream.Update(ctx, ls.GetID(), &management.LogStream{Name: auth0.String("renamed")}); err != nil {
				t.Errorf("update: %v", err)
			}
			if _, err := m.LogStream.List(ctx); err != nil {
				t.Errorf("list: %v", err)
			}
		}()
	}
	wg.Wait()
	srv.logDeliveries.Wait()

	if got := len(rcv.records(t, "JSONARRAY")); got != logins {
		t.Fatalf("delivered %d records, want %d", got, logins)
	}
}

func TestLogDeliveryDoesNotFollowRedirects(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	target := newLogReceiver(t, srv, 0)
	var redirects int
	var mu sync.Mutex
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		redirects++
		mu.Unlock()
		http.Redirect(w, r, target.ts.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	srv.logRetryBackoff = 0
	m := newMgmt(t, ts.URL)
	if err := m.LogStream.Create(context.Background(), httpStream("s", redirector.URL, "JSONARRAY")); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	if _, status, msg := loginToOrg(t, ts.URL, "+14155551234", "org_test", "openid"); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, msg)
	}
	srv.logDeliveries.Wait()

	mu.Lock()
	defer mu.Unlock()
	if redirects != logStreamDeliveryTries {
		t.Fatalf("redirecting receiver hit %d times, want %d retries", redirects, logStreamDeliveryTries)
	}
	if got := target.received(); len(got) != 0 {
		t.Fatalf("redirect target received %d deliveries", len(got))
	}
}

func TestExchangeLogNamesBasicAuthClient(t *testing.T) {
	srv := exchangeServer(t, &config.TokenExchangeAction{RequireClaim: exNS + "platform", Actor: true})
	srv.clients["spa_app"].Name = "PEE SPA"
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	rcv := streamTo(t, srv, ts.URL, "JSONARRAY")

	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {srv.signSubject(t, jwt.MapClaims{"sub": "auth0|admin", exNS + "platform": "admin"})},
		"subject_token_type": {exSubjectType},
		"target_org":         {"org_2"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("spa_app", "secret")
	rec := httptest.NewRecorder()
	srv.handleToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body)
	}
	srv.logDeliveries.Wait()

	recs := rcv.records(t, "JSONARRAY")
	if len(recs) != 1 || recs[0].Data["client_id"] != "spa_app" || recs[0].Data["client_name"] != "PEE SPA" {
		t.Fatalf("records = %+v", recs)
	}
}

func TestInvitationLoginLogNamesTicketConnection(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	rcv := streamTo(t, f.srv, f.ts.URL, "JSONARRAY")
	inv := f.invitation("ticket-conn@example.test")
	inv.ConnectionID = &f.connectionID
	if err := f.m.Organization.CreateInvitation(ctx, f.orgID, inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	// A wrong code first: the failure names the ticket's connection too.
	client := noRedirectClient()
	resp, err := client.Get(authorizeURLFromInvitation(t, f.ts.URL, inv.GetInvitationURL(), f.clientID))
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	sid := sessionIDRe.FindStringSubmatch(string(page))
	if len(sid) < 2 {
		t.Fatal("no session_id in login page")
	}
	resp, err = client.PostForm(f.ts.URL+"/authorize", url.Values{
		"session_id": {sid[1]}, "identifier": {"ticket-conn@example.test"}, "code": {"000000"},
	})
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	_ = resp.Body.Close()

	// The link carries no connection; the ticket's is authoritative.
	if tokens, st, msg := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), "ticket-conn@example.test", f.clientID); tokens == nil {
		t.Fatalf("accept: %d %s", st, msg)
	}
	f.srv.logDeliveries.Wait()

	recs := rcv.records(t, "JSONARRAY")
	if got := typesOf(recs); len(got) != 2 || !slices.Contains(got, "s") || !slices.Contains(got, "f") {
		t.Fatalf("types = %v, want s and f", got)
	}
	for _, r := range recs {
		if r.Data["connection"] != "enterprise-sso" || r.Data["connection_id"] != f.connectionID {
			t.Fatalf("%s record = %+v", r.Data["type"], r.Data)
		}
	}
}

func TestLogStreamRefusesMalformedValues(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := newMgmt(t, ts.URL)
	ctx := context.Background()

	ls := httpStream("ok", "https://x.example.test", "JSONARRAY")
	if err := m.LogStream.Create(ctx, ls); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := m.URI("log-streams", ls.GetID())

	// Management.Request, not the typed SDK call: the SDK cannot send null or
	// a wrong-typed sink field, which is exactly what is under test.
	for name, body := range map[string]map[string]any{
		"null name":            {"name": nil},
		"null status":          {"status": nil},
		"null isPriority":      {"isPriority": nil},
		"numeric content type": {"sink": map[string]any{"httpEndpoint": "https://x.example.test", "httpContentType": 7}},
		"null content format":  {"sink": map[string]any{"httpEndpoint": "https://x.example.test", "httpContentFormat": nil}},
		"null filters":         {"filters": nil},
		"string headers":       {"sink": map[string]any{"httpEndpoint": "https://x.example.test", "httpCustomHeaders": "X-A: b"}},
		"numeric header value": {"sink": map[string]any{"httpEndpoint": "https://x.example.test", "httpCustomHeaders": []any{map[string]any{"header": "X-A", "value": 1}}}},
		"null pii_config":      {"pii_config": nil},
		"null filter item":     {"filters": []any{nil}},
	} {
		if err := m.Request(ctx, http.MethodPatch, path, body); statusOf(err) != http.StatusBadRequest {
			t.Errorf("%s: %v, want 400", name, err)
		}
	}
	// m.NewRequest then a swapped body: a null body and trailing JSON cannot be
	// expressed as a Go payload, but the request still goes through the SDK.
	for name, raw := range map[string]string{"null body": "null", "trailing value": `{"name":"x"} {"name":"y"}`, "trailing brace": `{"name":"x"}}`} {
		req, err := m.NewRequest(ctx, http.MethodPatch, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Body = io.NopCloser(strings.NewReader(raw))
		req.ContentLength = int64(len(raw))
		req.Header.Set("Content-Type", "application/json")
		resp, err := m.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, resp.StatusCode)
		}
	}
	create := map[string]any{"type": "http", "sink": map[string]any{"httpEndpoint": "https://x.example.test", "httpContentFormat": false}}
	if err := m.Request(ctx, http.MethodPost, m.URI("log-streams"), create); statusOf(err) != http.StatusBadRequest {
		t.Errorf("create with boolean content format: %v, want 400", err)
	}

	got, err := m.LogStream.Read(ctx, ls.GetID())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.GetName() != "ok" || got.GetStatus() != "active" || got.Sink.(*management.LogStreamSinkHTTP).GetContentFormat() != "JSONARRAY" {
		t.Fatalf("refused updates changed the stream: %+v", got)
	}
}

func TestLoginLogNamesIdentityUsed(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	srv.SetUser("two_ids", &config.User{
		ID: "two_ids", Email: "two@example.test", Phone: "+14155550000", EmailVerified: true,
		Identities: []config.UserIdentity{
			{Connection: "sms", Provider: "sms", UserID: "two_ids"},
			{Connection: "email", Provider: "email", UserID: "two_ids"},
		},
	})
	rcv := streamTo(t, srv, ts.URL, "JSONARRAY")

	if _, status, msg := loginToOrg(t, ts.URL, "two@example.test", "", "openid"); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, msg)
	}
	srv.logDeliveries.Wait()

	recs := rcv.records(t, "JSONARRAY")
	if len(recs) != 1 || recs[0].Data["connection"] != "email" || recs[0].Data["connection_id"] != "con_email" {
		t.Fatalf("records = %+v", recs)
	}
}

func TestLogDeliverySendsCustomHeaders(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	rcv := newLogReceiver(t, srv, 0)
	m := newMgmt(t, ts.URL)
	ls := httpStream("s", rcv.ts.URL, "JSONARRAY")
	headers := []map[string]string{{"header": "X-Stream", "value": "pee"}}
	ls.Sink.(*management.LogStreamSinkHTTP).CustomHeaders = &headers
	if err := m.LogStream.Create(context.Background(), ls); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	if _, status, msg := loginToOrg(t, ts.URL, "+14155551234", "org_test", "openid"); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, msg)
	}
	srv.logDeliveries.Wait()

	if got := rcv.received(); len(got) != 1 || got[0].Header.Get("X-Stream") != "pee" {
		t.Fatalf("deliveries = %+v", got)
	}
}

func TestLoginLogUserNameIsIdentifierTyped(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	rcv := streamTo(t, srv, ts.URL, "JSONARRAY")
	// test_user_1 has an email too; an SMS sign-in logs the phone.
	if _, status, msg := loginToOrg(t, ts.URL, "+14155551234", "org_test", "openid"); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, msg)
	}
	srv.logDeliveries.Wait()

	recs := rcv.records(t, "JSONARRAY")
	if len(recs) != 1 || recs[0].Data["user_name"] != "+14155551234" {
		t.Fatalf("records = %+v", recs)
	}
}

func TestLogStreamCloneSharesNoState(t *testing.T) {
	l := &logStream{
		Sink:      map[string]any{"httpCustomHeaders": []any{map[string]any{"header": "X-A", "value": "a"}}},
		Filters:   []map[string]string{{"name": "auth.login.fail"}},
		PIIConfig: &logStreamPIIConfig{LogFields: []string{"email"}},
	}
	c := l.Clone()
	c.Sink["httpCustomHeaders"].([]any)[0].(map[string]any)["value"] = "changed"
	c.Filters[0]["name"] = "changed"
	c.PIIConfig.LogFields[0] = "changed"
	if l.Sink["httpCustomHeaders"].([]any)[0].(map[string]any)["value"] != "a" || l.Filters[0]["name"] != "auth.login.fail" || l.PIIConfig.LogFields[0] != "email" {
		t.Fatalf("clone mutation reached the original: %+v", l)
	}
}

func TestRevokedInvitationIsFailedLogin(t *testing.T) {
	f, cleanup := newInviteFixture(t)
	defer cleanup()
	ctx := context.Background()

	rcv := streamTo(t, f.srv, f.ts.URL, "JSONARRAY", "auth.login.fail")
	inv := f.createInvitation(t, "revoked@example.test")
	if err := f.m.Organization.DeleteInvitation(ctx, f.orgID, inv.GetID()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if tokens, _, _ := followInvitation(t, f.ts.URL, inv.GetInvitationURL(), "revoked@example.test", f.clientID); tokens != nil {
		t.Fatal("revoked invitation redeemed")
	}
	f.srv.logDeliveries.Wait()

	recs := rcv.records(t, "JSONARRAY")
	if len(recs) != 1 || recs[0].Data["type"] != "f" || recs[0].Data["organization_id"] != f.orgID {
		t.Fatalf("records = %+v", recs)
	}
}

func TestDeniedLoginIsFailedLogin(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	m := mgmt{t, ts.URL}
	m.deployBound("gate", `
		exports.onExecutePostLogin = async (event, api) => {
		  if (!event.request.query.approved) api.access.deny("not approved");
		};`)
	rcv := streamTo(t, srv, ts.URL, "JSONARRAY")

	if st, _ := login(t, ts, ""); st != http.StatusForbidden {
		t.Fatalf("denied login answered %d", st)
	}
	srv.logDeliveries.Wait()
	if got := typesOf(rcv.records(t, "JSONARRAY")); len(got) != 1 || got[0] != "f" {
		t.Fatalf("denied login logged %v, want [f]", got)
	}

	if st, _ := login(t, ts, "&approved=1"); st != http.StatusOK {
		t.Fatalf("approved login answered %d", st)
	}
	srv.logDeliveries.Wait()
	if got := typesOf(rcv.records(t, "JSONARRAY")); len(got) != 2 || got[1] != "s" {
		t.Fatalf("after approved login: %v, want [f s]", got)
	}
}

func TestUnknownOrganizationIsFailedLogin(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	rcv := streamTo(t, srv, ts.URL, "JSONARRAY")
	if _, status, _ := loginToOrg(t, ts.URL, "+14155551234", "org_missing", "openid"); status == http.StatusOK {
		t.Fatal("login to an unknown organization succeeded")
	}
	srv.logDeliveries.Wait()

	recs := rcv.records(t, "JSONARRAY")
	if len(recs) != 1 || recs[0].Data["type"] != "f" || recs[0].Data["organization_id"] != "org_missing" {
		t.Fatalf("records = %+v", recs)
	}
}

func TestLogStreamSubpathIsNotFound(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()
	m := newMgmt(t, ts.URL)
	ls := httpStream("s", "https://x.example.test", "JSONARRAY")
	if err := m.LogStream.Create(context.Background(), ls); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Request, not LogStream.Delete: no SDK method can name a subpath.
	err := m.Request(context.Background(), http.MethodDelete, m.URI("log-streams", ls.GetID(), "anything"), nil)
	if statusOf(err) != http.StatusNotFound {
		t.Fatalf("delete subpath: %v, want 404", err)
	}
	if _, err := m.LogStream.Read(context.Background(), ls.GetID()); err != nil {
		t.Fatalf("stream gone after subpath delete: %v", err)
	}
}
