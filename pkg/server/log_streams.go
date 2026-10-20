package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/contact"
)

// logStreamOAS holds the log stream schemas of Auth0's Management API OpenAPI
// document, verbatim. Behaviour the schemas do not state follows the responses
// recorded in go-auth0's test/data/recordings/TestLogStreamManager_*.
//
//go:embed log_stream_schemas.json
var logStreamOAS []byte

var logStreamSchemaCompiler = func() *jsonschema.Compiler {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(logStreamOAS))
	if err != nil {
		panic(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource("oas.json", doc); err != nil {
		panic(err)
	}
	return c
}()

func logStreamSchema(name string) *jsonschema.Schema {
	return logStreamSchemaCompiler.MustCompile("oas.json#/components/schemas/" + name)
}

var (
	createLogStreamSchema = logStreamSchema("CreateLogStreamRequestContent")
	updateLogStreamSchema = logStreamSchema("UpdateLogStreamRequestContent")
)

// logStreamType is a stream type's behaviour beyond its schema.
type logStreamType struct {
	// sinkPatch validates a sink PATCH; nil for the types LogStreamSinkPatch
	// leaves out, whose sink cannot be changed.
	sinkPatch *jsonschema.Schema
	// masked is the write-only sink field reads return as maskedSecret.
	masked string
	// generated is the sink field Auth0 fills in on create.
	generated func(s *Server) (field, value string)
	defaults  map[string]string
}

var logStreamTypes = map[string]logStreamType{
	"http": {
		sinkPatch: logStreamSchema("LogStreamHttpSink"),
		// Delivery needs both; these are what the dashboard preselects.
		defaults: map[string]string{"httpContentFormat": "JSONLINES", "httpContentType": "application/json"},
	},
	"eventbridge": {generated: func(s *Server) (string, string) {
		return "awsPartnerEventSource", fmt.Sprintf("aws.partner/auth0.com/%s-%s/auth0.logs", s.tenantHost(), uuid.NewString())
	}},
	"eventgrid": {generated: func(s *Server) (string, string) {
		return "azurePartnerTopic", fmt.Sprintf("auth0-logs-%s-%s", strings.ReplaceAll(s.tenantHost(), ".", "-"), uuid.NewString())
	}},
	"datadog": {sinkPatch: logStreamSchema("LogStreamDatadogSink")},
	"splunk":  {sinkPatch: logStreamSchema("LogStreamSplunkSink")},
	"sumo":    {sinkPatch: logStreamSchema("LogStreamSumoSink")},
	"segment": {sinkPatch: logStreamSchema("LogStreamSegmentSink")},
	"mixpanel": {
		sinkPatch: logStreamSchema("LogStreamMixpanelSinkPatch"),
		masked:    "mixpanelServiceAccountPassword",
	},
}

// priorityFilters is what Auth0 stores on a priority stream, whatever filters
// the request named.
var priorityFilters = []map[string]string{{"type": "category", "name": "security"}}

// logCategory maps the event types the mock emits to their filter category.
var logCategory = map[string]string{
	"s":     "auth.login.success",
	"f":     "auth.login.fail",
	"secte": "auth.token_exchange.success",
	"fecte": "auth.token_exchange.fail",
	// Device flow. Auth0's filter catalog lists fdecc under User/Behavioral
	// failures and fdeac under none, which leaves it in Other.
	"fdecc": "user.fail",
	"fdeac": "other",
}

var (
	// The rule go-auth0 documents on LogStream.Name.
	logStreamNamePattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9 -]*[A-Za-z0-9])?$`)
	maskedSecret            = "********"
	logStreamDeliveryTries  = 3
	defaultLogStreamBackoff = time.Second
)

// logStreamPIIConfig is LogStreamPiiConfig.
type logStreamPIIConfig struct {
	LogFields []string `json:"log_fields"`
	Method    string   `json:"method,omitempty"`
	Algorithm string   `json:"algorithm,omitempty"`
}

// logStream is a stored log stream, in Auth0's wire shape.
type logStream struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Type       string              `json:"type"`
	Status     string              `json:"status"`
	Sink       map[string]any      `json:"sink"`
	Filters    []map[string]string `json:"filters,omitempty"`
	IsPriority bool                `json:"isPriority"`
	PIIConfig  *logStreamPIIConfig `json:"pii_config,omitempty"`
}

// Clone returns a copy that shares no maps or slices with the original.
func (l *logStream) Clone() *logStream {
	out := *l
	out.Sink = deepCopy(l.Sink).(map[string]any)
	if l.Filters != nil {
		out.Filters = make([]map[string]string, len(l.Filters))
		for i, f := range l.Filters {
			out.Filters[i] = maps.Clone(f)
		}
	}
	if l.PIIConfig != nil {
		p := *l.PIIConfig
		p.LogFields = slices.Clone(p.LogFields)
		out.PIIConfig = &p
	}
	return &out
}

// response is the stream as Auth0 returns it: write-only secrets masked.
func (l *logStream) response() *logStream {
	out := l.Clone()
	if k := logStreamTypes[l.Type].masked; out.Sink[k] != nil {
		out.Sink[k] = maskedSecret
	}
	return out
}

// tenantHost is the tenant domain, as Auth0 names it in generated sink values.
func (s *Server) tenantHost() string {
	if u, err := url.Parse(s.cfg.Issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return "mock.auth0.local"
}

// auth0Message is an error whose text is Auth0's message verbatim.
type auth0Message string

func (e auth0Message) Error() string { return string(e) }

const errLogStreamNotFound = auth0Message("The log stream does not exist.")

func payloadErr(format string, args ...any) error {
	return auth0Message("Payload validation error: " + fmt.Sprintf(format, args...))
}

// logStreamRequest is a create or update body. Pointers tell an absent field
// from a zero value.
type logStreamRequest struct {
	Name       *string              `json:"name"`
	Type       string               `json:"type"`
	Status     *string              `json:"status"`
	Sink       json.RawMessage      `json:"sink"`
	Filters    *[]map[string]string `json:"filters"`
	IsPriority *bool                `json:"isPriority"`
	PIIConfig  *logStreamPIIConfig  `json:"pii_config"`
	StartFrom  *string              `json:"startFrom"`
}

func decodeLogStreamRequest(r *http.Request, schema *jsonschema.Schema) (*logStreamRequest, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, payloadErr("'Invalid JSON'.")
	}
	var req logStreamRequest
	if err := decodeValid(schema, raw, &req); err != nil {
		return nil, err
	}
	if req.Name != nil && !logStreamNamePattern.MatchString(*req.Name) {
		return nil, payloadErr("'String does not match pattern' on property name.")
	}
	// go-auth0 documents startFrom as an ISO 8601 datetime.
	if req.StartFrom != nil {
		if _, err := time.Parse(time.RFC3339Nano, *req.StartFrom); err != nil {
			return nil, payloadErr("'Invalid date-time' on property startFrom.")
		}
	}
	return &req, nil
}

// decodeValid validates raw against schema, then decodes it into dst.
func decodeValid(schema *jsonschema.Schema, raw []byte, dst any) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return payloadErr("'Invalid JSON'.")
	}
	if err := schema.Validate(inst); err != nil {
		// The innermost cause names the offending property.
		var ve *jsonschema.ValidationError
		for errors.As(err, &ve) && len(ve.Causes) > 0 {
			err = ve.Causes[0]
		}
		return payloadErr("'%s'.", err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return payloadErr("'%s'.", err)
	}
	return nil
}

// apply sets the fields present in req on l.
func (l *logStream) apply(req *logStreamRequest) {
	if req.Name != nil {
		l.Name = *req.Name
	}
	if req.Status != nil {
		l.Status = *req.Status
	}
	if req.Filters != nil {
		l.Filters = *req.Filters
	}
	if req.IsPriority != nil {
		l.IsPriority = *req.IsPriority
	}
	if l.IsPriority {
		l.Filters = slices.Clone(priorityFilters)
	}
	if req.PIIConfig != nil {
		l.PIIConfig = req.PIIConfig
	}
}

func (s *Server) handleLogStreams(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		all := make([]*logStream, 0, len(s.logStreams))
		for _, l := range s.logStreams {
			all = append(all, l.response())
		}
		s.mu.RUnlock()
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		// A bare array: GET /log-streams takes no pagination parameters.
		_ = json.NewEncoder(w).Encode(all)
	case http.MethodPost:
		s.createLogStream(w, r)
	case http.MethodOptions:
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleLogStream(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w, r)
	w.Header().Set("Content-Type", "application/json")

	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v2/log-streams/"), "/")
	if id == "" || strings.Contains(id, "/") {
		writeAuth0Error(w, http.StatusNotFound, "Not Found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		l, ok := s.logStreams[id]
		if ok {
			l = l.response()
		}
		s.mu.RUnlock()
		if !ok {
			writeAuth0Error(w, http.StatusNotFound, errLogStreamNotFound.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(l)
	case http.MethodPatch:
		s.updateLogStream(w, r, id)
	case http.MethodDelete:
		// 204 whether or not the stream exists, as Auth0 answers a repeated delete.
		s.mu.Lock()
		delete(s.logStreams, id)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case http.MethodOptions:
	default:
		writeAuth0Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) createLogStream(w http.ResponseWriter, r *http.Request) {
	req, err := decodeLogStreamRequest(r, createLogStreamSchema)
	if err != nil {
		writeAuth0Error(w, http.StatusBadRequest, err.Error())
		return
	}
	l := &logStream{Name: req.Type, Type: req.Type, Status: "active"}
	if err := json.Unmarshal(req.Sink, &l.Sink); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, payloadErr("'%s'.", err).Error())
		return
	}
	l.apply(req)
	t := logStreamTypes[l.Type]
	for k, v := range t.defaults {
		if _, ok := l.Sink[k]; !ok {
			l.Sink[k] = v
		}
	}
	if t.generated != nil {
		k, v := t.generated(s)
		l.Sink[k] = v
	}

	s.mu.Lock()
	l.ID = "lst_" + s.generateID()
	s.logStreams[l.ID] = l
	out := l.response()
	s.mu.Unlock()

	// Auth0 answers 200 here, not 201.
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) updateLogStream(w http.ResponseWriter, r *http.Request, id string) {
	req, err := decodeLogStreamRequest(r, updateLogStreamSchema)
	if err != nil {
		writeAuth0Error(w, http.StatusBadRequest, err.Error())
		return
	}
	status, out, err := s.patchLogStream(id, req)
	if err != nil {
		writeAuth0Error(w, status, err.Error())
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

// patchLogStream applies req under the lock and returns the response, so
// nothing is written to the client while the lock is held.
func (s *Server) patchLogStream(id string, req *logStreamRequest) (int, *logStream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.logStreams[id]
	if !ok {
		return http.StatusNotFound, nil, errLogStreamNotFound
	}
	// Changed on a copy, so a refused update leaves the stream as it was.
	next := stored.Clone()
	if req.Sink != nil {
		schema := logStreamTypes[next.Type].sinkPatch
		if schema == nil {
			return http.StatusBadRequest, nil, payloadErr("'sink cannot be updated for log streams of type %s'.", next.Type)
		}
		var sink map[string]any
		if err := decodeValid(schema, req.Sink, &sink); err != nil {
			return http.StatusBadRequest, nil, err
		}
		maps.Copy(next.Sink, sink)
	}
	next.apply(req)
	s.logStreams[id] = next
	return http.StatusOK, next.response(), nil
}

// matches reports whether the stream takes an event of this type: active, and
// either unfiltered or filtered to its category.
func (l *logStream) matches(eventType string) bool {
	return l.Status == "active" && (len(l.Filters) == 0 || slices.ContainsFunc(l.Filters, func(f map[string]string) bool {
		return f["name"] == logCategory[eventType]
	}))
}

// logRecord is one delivered event: Auth0 wraps the log in log_id and data.
type logRecord struct {
	LogID string         `json:"log_id"`
	Data  map[string]any `json:"data"`
}

// emitLog records a tenant log event and delivers it to every matching http
// stream. Delivery runs in the background, so a slow receiver never holds up
// the login that produced the event.
func (s *Server) emitLog(data map[string]any) {
	data["date"] = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	data["tenant_name"] = "mock"
	data["environment_name"] = "mock"
	// Failures carry the message in details.error, as Auth0's sample failed
	// login log does.
	if t, _ := data["type"].(string); strings.HasPrefix(t, "f") {
		if d, ok := data["details"].(map[string]any); ok {
			d["error"] = map[string]any{"message": data["description"]}
		}
	}

	s.mu.Lock()
	logID := fmt.Sprintf("900%020d%s", time.Now().UnixNano(), s.generateID()[:8])
	var targets []*logStream
	for _, l := range s.logStreams {
		if l.Type == "http" && l.matches(data["type"].(string)) {
			targets = append(targets, l.Clone())
		}
	}
	s.mu.Unlock()

	data["log_id"] = logID
	rec := logRecord{LogID: logID, Data: data}
	for _, l := range targets {
		// Add/Done rather than WaitGroup.Go: go.mod targets 1.24.
		s.logDeliveries.Add(1)
		go func() {
			defer s.logDeliveries.Done()
			s.deliverLog(l, rec)
		}()
	}
}

// deliverLog POSTs rec to the stream, retrying a non-2xx answer as Auth0 does.
func (s *Server) deliverLog(l *logStream, rec logRecord) {
	body, err := encodeLogBatch(l.Sink["httpContentFormat"].(string), []logRecord{rec})
	if err != nil {
		log.Printf("log stream %s: encode: %v", l.ID, err)
		return
	}
	endpoint, _ := l.Sink["httpEndpoint"].(string)
	contentType, _ := l.Sink["httpContentType"].(string)
	authorization, _ := l.Sink["httpAuthorization"].(string)

	for attempt := 1; attempt <= logStreamDeliveryTries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			log.Printf("log stream %s: request: %v", l.ID, err)
			return
		}
		req.Header.Set("Content-Type", contentType)
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		if headers, ok := l.Sink["httpCustomHeaders"].([]any); ok {
			for _, h := range headers {
				if m, ok := h.(map[string]any); ok {
					name, _ := m["header"].(string)
					value, _ := m["value"].(string)
					if name != "" {
						req.Header.Set(name, value)
					}
				}
			}
		}
		client, err := s.deliveryClient()
		var resp *http.Response
		if err == nil {
			resp, err = client.Do(req)
		}
		if err == nil {
			// Drained, bounded, so the connection is reused for the next event.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				return
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		log.Printf("log stream %s: delivery attempt %d: %v", l.ID, attempt, err)
		if attempt < logStreamDeliveryTries {
			time.Sleep(s.logRetryBackoff)
		}
	}
}

// encodeLogBatch renders records in the stream's content format.
func encodeLogBatch(format string, recs []logRecord) ([]byte, error) {
	switch format {
	case "JSONARRAY":
		return json.Marshal(recs)
	case "JSONOBJECT":
		return json.Marshal(map[string]any{"logs": recs})
	default:
		var buf bytes.Buffer
		for _, r := range recs {
			line, err := json.Marshal(r)
			if err != nil {
				return nil, err
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		return buf.Bytes(), nil
	}
}

// logDeliveryClient builds the client streams are delivered with.
func logDeliveryClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		// A redirect is a non-2xx answer to retry, not a delivery to follow:
		// following it would count the redirect target's 200 as success and
		// carry the authorization header to it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// deliveryClient is the client for one delivery attempt. LogStreamCAFile adds a
// CA to the system pool, for a receiver behind a locally issued certificate. It
// is read per attempt, so the CA may be issued or rotated after the mock starts;
// until it can be read, attempts fail and are retried like any other.
func (s *Server) deliveryClient() (*http.Client, error) {
	caFile := s.cfg.LogStreamCAFile
	if caFile == "" {
		return s.logDeliveryClient, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("log stream CA: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("log stream CA: no certificates in %s", caFile)
	}
	// Cloned so proxy, dial and HTTP/2 settings stay as the default client's.
	// Keep-alives off: the client lives for one attempt, so a pooled connection
	// would only be left open.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	transport.DisableKeepAlives = true
	client := *s.logDeliveryClient
	client.Transport = transport
	return &client, nil
}

// emitLoginLog records a sign-in outcome from the /authorize form. user is nil
// when the identifier matched no account; identifier is then the user_name, as
// Auth0 logs what was typed.
func (s *Server) emitLoginLog(r *http.Request, params url.Values, eventType, description string, user *config.User, identifier, orgID string) {
	s.emitLog(s.loginLog(r, params, eventType, description, user, identifier, orgID))
}

// loginLog builds a sign-in record from the /authorize request without
// emitting it, so a success can wait for the post-login Action's verdict.
func (s *Server) loginLog(r *http.Request, params url.Values, eventType, description string, user *config.User, identifier, orgID string) map[string]any {
	data := map[string]any{
		"type":        eventType,
		"description": description,
		"client_id":   params.Get("client_id"),
		"ip":          clientIP(r),
		"user_agent":  r.UserAgent(),
		"user_name":   identifier,
		"connection":  params.Get("connection"),
		"hostname":    r.Host,
		"client_name": "",
		"details":     map[string]any{},
	}
	if user != nil {
		data["user_id"] = user.ID
		if data["connection"] == "" {
			data["connection"] = identityConnection(user, identifier)
		}
	}

	s.mu.RLock()
	if c, ok := s.clients[params.Get("client_id")]; ok {
		data["client_name"] = c.Name
	}
	data["strategy"], data["strategy_type"] = "", ""
	if id := s.connectionIDByName(data["connection"].(string)); id != "" {
		data["connection_id"] = id
		strategy := s.connections[id].Strategy
		data["strategy"], data["strategy_type"] = strategy, strategyType(strategy)
	}
	// Failure logs carry whatever organization was asked for, valid or not.
	if orgID != "" {
		data["organization_id"] = orgID
		if org, ok := s.organizations[orgID]; ok {
			data["organization_name"] = org.Name
		}
	}
	s.mu.RUnlock()

	return data
}

// emitPendingLogin finishes a sign-in record held on an auth code: a success,
// or a failure when the post-login Action refused the login.
func (s *Server) emitPendingLogin(pending map[string]any, allowed bool) {
	if pending == nil {
		return
	}
	if !allowed {
		pending["type"] = "f"
		pending["description"] = "Access denied by a post-login action."
	}
	s.emitLog(pending)
}

// emitExchangeLog records a Custom Token Exchange outcome. sub is the subject
// token's subject once verified, and the actor on success.
func (s *Server) emitExchangeLog(r *http.Request, eventType, description, sub, orgID string) {
	clientID := clientIDFromRequest(r)
	details := map[string]any{"subject_token_type": r.FormValue("subject_token_type")}
	data := map[string]any{
		"type":        eventType,
		"description": description,
		"client_id":   clientID,
		"ip":          clientIP(r),
		"user_agent":  r.UserAgent(),
		"audience":    s.cfg.Audience,
		"hostname":    r.Host,
		"client_name": "",
		"details":     details,
	}
	if sub != "" {
		data["user_id"] = sub
		if eventType == "secte" && s.cfg.Actions.TokenExchange.Actor {
			details["actor"] = map[string]any{"sub": sub}
		}
	}

	s.mu.RLock()
	if c, ok := s.clients[clientID]; ok {
		data["client_name"] = c.Name
	}
	if orgID != "" {
		data["organization_id"] = orgID
		if org, ok := s.organizations[orgID]; ok {
			data["organization_name"] = org.Name
		}
	}
	s.mu.RUnlock()

	s.emitLog(data)
}

// identityConnection names the connection a passwordless sign-in went through:
// the identity matching the kind of identifier typed, else the first.
func identityConnection(user *config.User, identifier string) string {
	want := "sms"
	if contact.IsEmail(identifier) {
		want = "email"
	}
	for _, id := range user.Identities {
		if id.Provider == want {
			return id.Connection
		}
	}
	if len(user.Identities) > 0 {
		return user.Identities[0].Connection
	}
	return ""
}

// deepCopy copies a decoded JSON value, so nested maps and slices are not
// shared with the original.
func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if t == nil {
			return t
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		if t == nil {
			return t
		}
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = deepCopy(e)
		}
		return out
	default:
		return v
	}
}

// strategyType is Auth0's grouping of a connection strategy, as logs report it.
func strategyType(strategy string) string {
	switch strategy {
	case "email", "sms":
		return "passwordless"
	case "auth0":
		return "database"
	case "samlp", "oidc", "okta", "waad", "adfs", "ad", "pingfederate", "google-apps", "office365":
		return "enterprise"
	case "":
		return ""
	default:
		return "social"
	}
}
