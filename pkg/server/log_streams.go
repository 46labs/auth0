package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/contact"
)

// The schemas below follow Auth0's Management API OpenAPI document
// (https://auth0.com/docs/oas/management/v2/management-api-oas.json) and the
// responses recorded in go-auth0's test/data/recordings/TestLogStreamManager_*.

// logStreamFilterNames is LogStreamFilterGroupNameEnum.
var logStreamFilterNames = []string{
	"auth.login.fail", "auth.login.notification", "auth.login.success",
	"auth.logout.fail", "auth.logout.success",
	"auth.signup.fail", "auth.signup.success",
	"auth.silent_auth.fail", "auth.silent_auth.success",
	"auth.token_exchange.fail", "auth.token_exchange.success",
	"management.fail", "management.success",
	"scim.event", "system.notification",
	"user.fail", "user.notification", "user.success",
	"actions", "other",
}

// priorityFilters is what Auth0 stores on a priority stream, whatever filters
// the request named (recorded create and update responses).
var priorityFilters = []map[string]string{{"type": "category", "name": "security"}}

// logCategory maps the event types the mock emits to their filter category.
var logCategory = map[string]string{
	"s":     "auth.login.success",
	"f":     "auth.login.fail",
	"secte": "auth.token_exchange.success",
	"fecte": "auth.token_exchange.fail",
}

var (
	logStreamStatuses       = []string{"active", "paused", "suspended"}
	logStreamNamePattern    = regexp.MustCompile(`^[A-Za-z0-9 -]+$`)
	logStreamCreateFields   = []string{"name", "type", "sink", "filters", "isPriority", "pii_config", "startFrom"}
	logStreamUpdateFields   = []string{"name", "status", "sink", "filters", "isPriority", "pii_config"}
	piiLogFields            = []string{"first_name", "last_name", "username", "email", "phone", "address"}
	maskedSecret            = "********"
	logStreamDeliveryTries  = 3
	defaultLogStreamBackoff = time.Second
)

// sinkField is one sink property's schema.
type sinkField struct {
	kind    string // "string", "boolean" or "array"
	pattern *regexp.Regexp
	enum    []string
}

// sinkSchema is one stream type's sink. patchRequired is nil for the types the
// update schema (LogStreamSinkPatch) leaves out, whose sink cannot be changed.
type sinkSchema struct {
	fields         map[string]sinkField
	required       []string
	patchRequired  []string
	masked         []string
	generate       func(s *Server) (string, string)
	patchable      bool
	defaultsOnSave map[string]string
}

var (
	strField     = sinkField{kind: "string"}
	digits       = regexp.MustCompile(`^[0-9]*$`)
	noColon      = regexp.MustCompile(`^[^:]+$`)
	awsAccountID = regexp.MustCompile(`^\d{12}$`)
	azureSubID   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	httpsURL     = regexp.MustCompile(`^https://.*`)
)

var sinkSchemas = map[string]sinkSchema{
	"http": {
		fields: map[string]sinkField{
			"httpAuthorization": strField,
			"httpContentFormat": {kind: "string", enum: []string{"JSONARRAY", "JSONLINES", "JSONOBJECT"}},
			"httpContentType":   strField,
			"httpEndpoint":      {kind: "string", pattern: httpsURL},
			"httpCustomHeaders": {kind: "array"},
		},
		required:      []string{"httpEndpoint"},
		patchRequired: []string{"httpEndpoint"},
		patchable:     true,
		// Delivery needs a format and a type; JSONLINES and application/json are
		// what the dashboard preselects.
		defaultsOnSave: map[string]string{"httpContentFormat": "JSONLINES", "httpContentType": "application/json"},
	},
	"eventbridge": {
		fields: map[string]sinkField{
			"awsAccountId":          {kind: "string", pattern: awsAccountID},
			"awsRegion":             {kind: "string", enum: awsRegions},
			"awsPartnerEventSource": strField,
		},
		required: []string{"awsAccountId", "awsRegion"},
		generate: func(s *Server) (string, string) {
			return "awsPartnerEventSource", fmt.Sprintf("aws.partner/auth0.com/%s-%s/auth0.logs", s.tenantHost(), uuid.NewString())
		},
	},
	"eventgrid": {
		fields: map[string]sinkField{
			"azureSubscriptionId": {kind: "string", pattern: azureSubID},
			"azureRegion":         {kind: "string", enum: azureRegions},
			"azureResourceGroup":  strField,
			"azurePartnerTopic":   strField,
		},
		required: []string{"azureSubscriptionId", "azureRegion", "azureResourceGroup"},
		generate: func(s *Server) (string, string) {
			return "azurePartnerTopic", fmt.Sprintf("auth0-logs-%s-%s", strings.ReplaceAll(s.tenantHost(), ".", "-"), uuid.NewString())
		},
	},
	"datadog": {
		fields: map[string]sinkField{
			"datadogApiKey": strField,
			"datadogRegion": {kind: "string", enum: []string{"us", "eu", "us3", "us5"}},
		},
		required:      []string{"datadogApiKey", "datadogRegion"},
		patchRequired: []string{"datadogApiKey", "datadogRegion"},
		patchable:     true,
	},
	"splunk": {
		fields: map[string]sinkField{
			"splunkDomain": strField,
			"splunkPort":   {kind: "string", pattern: digits},
			"splunkToken":  strField,
			"splunkSecure": {kind: "boolean"},
		},
		required:      []string{"splunkDomain", "splunkToken", "splunkPort", "splunkSecure"},
		patchRequired: []string{"splunkDomain", "splunkToken", "splunkPort", "splunkSecure"},
		patchable:     true,
	},
	"sumo": {
		fields:        map[string]sinkField{"sumoSourceAddress": strField},
		required:      []string{"sumoSourceAddress"},
		patchRequired: []string{"sumoSourceAddress"},
		patchable:     true,
	},
	"segment": {
		fields:        map[string]sinkField{"segmentWriteKey": strField},
		required:      []string{"segmentWriteKey"},
		patchRequired: []string{},
		patchable:     true,
	},
	"mixpanel": {
		fields: map[string]sinkField{
			"mixpanelRegion":                 {kind: "string", enum: []string{"us", "eu"}},
			"mixpanelProjectId":              {kind: "string", pattern: regexp.MustCompile(`^\d+$`)},
			"mixpanelServiceAccountUsername": {kind: "string", pattern: noColon},
			"mixpanelServiceAccountPassword": {kind: "string", pattern: noColon},
		},
		required:      []string{"mixpanelRegion", "mixpanelProjectId", "mixpanelServiceAccountUsername", "mixpanelServiceAccountPassword"},
		patchRequired: []string{"mixpanelRegion", "mixpanelProjectId", "mixpanelServiceAccountUsername"},
		masked:        []string{"mixpanelServiceAccountPassword"},
		patchable:     true,
	},
}

var awsRegions = []string{
	"af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
	"ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ca-central-1", "ca-west-1", "eu-central-1",
	"eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3",
	"il-central-1", "me-central-1", "me-south-1", "mx-central-1", "sa-east-1", "us-gov-east-1",
	"us-gov-west-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
}

var azureRegions = []string{
	"australiacentral", "australiaeast", "australiasoutheast", "brazilsouth", "canadacentral", "canadaeast",
	"centralindia", "centralus", "eastasia", "eastus", "eastus2", "francecentral", "germanywestcentral",
	"japaneast", "japanwest", "koreacentral", "koreasouth", "northcentralus", "northeurope", "norwayeast",
	"southafricanorth", "southcentralus", "southeastasia", "southindia", "swedencentral", "switzerlandnorth",
	"uaenorth", "uksouth", "ukwest", "westcentralus", "westeurope", "westindia", "westus", "westus2",
}

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
	for _, k := range sinkSchemas[l.Type].masked {
		if _, ok := out.Sink[k]; ok {
			out.Sink[k] = maskedSecret
		}
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

// payloadError is a request refusal worded as Auth0 words it, so the message
// reaches the client verbatim rather than following Go's error-string style.
type payloadError string

func (e payloadError) Error() string { return "Payload validation error: " + string(e) }

// auth0Message is an error whose text is Auth0's message verbatim.
type auth0Message string

func (e auth0Message) Error() string { return string(e) }

const errLogStreamNotFound = auth0Message("The log stream does not exist.")

func payloadErr(format string, args ...any) error {
	return payloadError(fmt.Sprintf(format, args...))
}

// logStreamBody is a create or update request. Fields are raw so presence can be
// told apart from a zero value, and unknown fields are refused, as the schemas'
// additionalProperties: false does.
type logStreamBody map[string]json.RawMessage

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
			writeAuth0Error(w, http.StatusNotFound, "The log stream does not exist.")
			return
		}
		_ = json.NewEncoder(w).Encode(l)
	case http.MethodPatch:
		s.updateLogStream(w, r, id)
	case http.MethodDelete:
		// 204 whether or not the stream exists, as Auth0's recorded traffic
		// answers a repeated delete.
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
	body, err := decodeLogStreamBody(r, logStreamCreateFields)
	if err != nil {
		writeAuth0Error(w, http.StatusBadRequest, err.Error())
		return
	}

	l := &logStream{Status: "active"}
	if err := body.str("type", &l.Type); err != nil || l.Type == "" {
		writeAuth0Error(w, http.StatusBadRequest, "Payload validation error: 'Missing required property: type'.")
		return
	}
	schema, ok := sinkSchemas[l.Type]
	if !ok {
		writeAuth0Error(w, http.StatusBadRequest, fmt.Sprintf("Payload validation error: 'No enum match for: %q' on property type.", l.Type))
		return
	}
	rawSink, ok := body["sink"]
	if !ok {
		writeAuth0Error(w, http.StatusBadRequest, "Payload validation error: 'Missing required property: sink'.")
		return
	}
	var startFrom string
	if err := body.str("startFrom", &startFrom); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, err.Error())
		return
	}
	// go-auth0 documents startFrom as an ISO 8601 datetime.
	if _, present := body["startFrom"]; present {
		if _, err := time.Parse(time.RFC3339Nano, startFrom); err != nil {
			writeAuth0Error(w, http.StatusBadRequest, "Payload validation error: 'Invalid date-time' on property startFrom.")
			return
		}
	}
	sink, err := schema.decode(rawSink, schema.required)
	if err != nil {
		writeAuth0Error(w, http.StatusBadRequest, err.Error())
		return
	}
	l.Sink = sink
	if err := l.apply(body); err != nil {
		writeAuth0Error(w, http.StatusBadRequest, err.Error())
		return
	}
	for k, v := range schema.defaultsOnSave {
		if _, ok := l.Sink[k]; !ok {
			l.Sink[k] = v
		}
	}
	if schema.generate != nil {
		k, v := schema.generate(s)
		l.Sink[k] = v
	}
	if l.Name == "" {
		l.Name = l.Type
	}

	s.mu.Lock()
	l.ID = "lst_" + s.generateID()
	s.logStreams[l.ID] = l
	out := l.response()
	s.mu.Unlock()

	// Auth0 answers 200 here, not 201 (go-auth0 recorded traffic).
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) updateLogStream(w http.ResponseWriter, r *http.Request, id string) {
	body, err := decodeLogStreamBody(r, logStreamUpdateFields)
	if err != nil {
		writeAuth0Error(w, http.StatusBadRequest, err.Error())
		return
	}

	status, out, err := s.patchLogStream(id, body)
	if err != nil {
		writeAuth0Error(w, status, err.Error())
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

// patchLogStream applies body to the stored stream under the lock and returns
// the response, so nothing is written to the client while the lock is held.
func (s *Server) patchLogStream(id string, body logStreamBody) (int, *logStream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.logStreams[id]
	if !ok {
		return http.StatusNotFound, nil, errLogStreamNotFound
	}
	// Validated on a copy, so a refused update leaves the stream as it was.
	next := stored.Clone()
	if rawSink, ok := body["sink"]; ok {
		schema := sinkSchemas[next.Type]
		if !schema.patchable {
			return http.StatusBadRequest, nil, payloadErr("'sink cannot be updated for log streams of type %s'.", next.Type)
		}
		sink, err := schema.decode(rawSink, schema.patchRequired)
		if err != nil {
			return http.StatusBadRequest, nil, err
		}
		maps.Copy(next.Sink, sink)
	}
	if err := next.apply(body); err != nil {
		return http.StatusBadRequest, nil, err
	}
	s.logStreams[id] = next
	return http.StatusOK, next.response(), nil
}

func decodeLogStreamBody(r *http.Request, allowed []string) (logStreamBody, error) {
	var body logStreamBody
	dec := json.NewDecoder(r.Body)
	// One JSON object and nothing after it: null decodes to a nil map, and a
	// second value would otherwise be ignored.
	if err := dec.Decode(&body); err != nil || body == nil {
		return nil, payloadErr("'Invalid JSON'.")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, payloadErr("'Invalid JSON'.")
	}
	for k := range body {
		if !slices.Contains(allowed, k) {
			return nil, payloadErr("'Additional properties not allowed: %s'.", k)
		}
	}
	return body, nil
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func (b logStreamBody) str(key string, dst *string) error {
	raw, ok := b[key]
	if !ok {
		return nil
	}
	// json.Unmarshal accepts null into a string by leaving it unchanged.
	if err := json.Unmarshal(raw, dst); err != nil || isNull(raw) {
		return payloadErr("'Expected type string' on property %s.", key)
	}
	return nil
}

// decode validates a sink object against the type's schema.
func (sc sinkSchema) decode(raw json.RawMessage, required []string) (map[string]any, error) {
	var sink map[string]any
	if err := json.Unmarshal(raw, &sink); err != nil || sink == nil {
		return nil, payloadErr("'Expected type object' on property sink.")
	}
	for _, k := range required {
		if _, ok := sink[k]; !ok {
			return nil, payloadErr("'Missing required property: %s' on property sink.", k)
		}
	}
	for k, v := range sink {
		f, ok := sc.fields[k]
		if !ok {
			return nil, payloadErr("'Additional properties not allowed: %s' on property sink.", k)
		}
		if err := f.check("sink."+k, v); err != nil {
			return nil, err
		}
	}
	return sink, nil
}

func (f sinkField) check(prop string, v any) error {
	switch f.kind {
	case "boolean":
		if _, ok := v.(bool); !ok {
			return payloadErr("'Expected type boolean' on property %s.", prop)
		}
	case "array":
		// httpCustomHeaders: HttpCustomHeader objects, header and value strings.
		items, ok := v.([]any)
		if !ok {
			return payloadErr("'Expected type array' on property %s.", prop)
		}
		for _, it := range items {
			m, ok := it.(map[string]any)
			if !ok {
				return payloadErr("'Expected type object' on property %s.", prop)
			}
			for _, k := range []string{"header", "value"} {
				if hv, present := m[k]; present {
					if _, ok := hv.(string); !ok {
						return payloadErr("'Expected type string' on property %s.%s.", prop, k)
					}
				}
			}
		}
	default:
		s, ok := v.(string)
		if !ok {
			return payloadErr("'Expected type string' on property %s.", prop)
		}
		if f.enum != nil && !slices.Contains(f.enum, s) {
			return payloadErr("'No enum match for: %q' on property %s.", s, prop)
		}
		if f.pattern != nil && !f.pattern.MatchString(s) {
			return payloadErr("'String does not match pattern' on property %s.", prop)
		}
	}
	return nil
}

// apply merges the top-level fields present in body into l.
func (l *logStream) apply(b logStreamBody) error {
	if _, ok := b["name"]; ok {
		if err := b.str("name", &l.Name); err != nil {
			return err
		}
		// The rule go-auth0 documents on LogStream.Name.
		if !logStreamNamePattern.MatchString(l.Name) ||
			strings.HasPrefix(l.Name, "-") || strings.HasSuffix(l.Name, "-") ||
			strings.TrimSpace(l.Name) != l.Name {
			return payloadErr("'String does not match pattern' on property name.")
		}
	}
	if _, ok := b["status"]; ok {
		if err := b.str("status", &l.Status); err != nil {
			return err
		}
		if !slices.Contains(logStreamStatuses, l.Status) {
			return payloadErr("'No enum match for: %q' on property status.", l.Status)
		}
	}
	if raw, ok := b["filters"]; ok {
		var filters []map[string]string
		if err := json.Unmarshal(raw, &filters); err != nil || isNull(raw) {
			return payloadErr("'Expected type array' on property filters.")
		}
		for _, f := range filters {
			// LogStreamFilter items are objects; null decodes to a nil map.
			if f == nil {
				return payloadErr("'Expected type object' on property filters.")
			}
			if t, ok := f["type"]; ok && t != "category" {
				return payloadErr("'No enum match for: %q' on property filters.type.", t)
			}
			if n, ok := f["name"]; ok && !slices.Contains(logStreamFilterNames, n) {
				return payloadErr("'No enum match for: %q' on property filters.name.", n)
			}
		}
		l.Filters = filters
	}
	if raw, ok := b["isPriority"]; ok {
		if err := json.Unmarshal(raw, &l.IsPriority); err != nil || isNull(raw) {
			return payloadErr("'Expected type boolean' on property isPriority.")
		}
	}
	if l.IsPriority {
		l.Filters = slices.Clone(priorityFilters)
	}
	if raw, ok := b["pii_config"]; ok {
		p, err := decodePIIConfig(raw)
		if err != nil {
			return err
		}
		l.PIIConfig = p
	}
	return nil
}

func decodePIIConfig(raw json.RawMessage) (*logStreamPIIConfig, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, payloadErr("'Expected type object' on property pii_config.")
	}
	for k := range m {
		if !slices.Contains([]string{"log_fields", "method", "algorithm"}, k) {
			return nil, payloadErr("'Additional properties not allowed: %s' on property pii_config.", k)
		}
	}
	if _, ok := m["log_fields"]; !ok {
		return nil, payloadErr("'Missing required property: log_fields' on property pii_config.")
	}
	var p logStreamPIIConfig
	if err := json.Unmarshal(raw, &p); err != nil || isNull(m["log_fields"]) {
		return nil, payloadErr("'Expected type array' on property pii_config.log_fields.")
	}
	if len(p.LogFields) == 0 {
		return nil, payloadErr("'Array is too short' on property pii_config.log_fields.")
	}
	for _, f := range p.LogFields {
		if !slices.Contains(piiLogFields, f) {
			return nil, payloadErr("'No enum match for: %q' on property pii_config.log_fields.", f)
		}
	}
	if _, ok := m["method"]; ok && p.Method != "mask" && p.Method != "hash" {
		return nil, payloadErr("'No enum match for: %q' on property pii_config.method.", p.Method)
	}
	if _, ok := m["algorithm"]; ok && p.Algorithm != "xxhash" {
		return nil, payloadErr("'No enum match for: %q' on property pii_config.algorithm.", p.Algorithm)
	}
	return &p, nil
}

// matches reports whether the stream takes an event of this type: active, and
// either unfiltered or filtered to its category.
func (l *logStream) matches(eventType string) bool {
	if l.Status != "active" {
		return false
	}
	if len(l.Filters) == 0 {
		return true
	}
	category := logCategory[eventType]
	for _, f := range l.Filters {
		if f["name"] == category {
			return true
		}
	}
	return false
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
		resp, err := s.logDeliveryClient.Do(req)
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

// logDeliveryClient builds the client streams are delivered with. caFile adds a
// CA to the system pool, for a receiver behind a locally issued certificate.
func logDeliveryClient(caFile string) (*http.Client, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		// A redirect is a non-2xx answer to retry, not a delivery to follow:
		// following it would count the redirect target's 200 as success and
		// carry the authorization header to it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if caFile == "" {
		return client, nil
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	client.Transport = transport
	return client, nil
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
