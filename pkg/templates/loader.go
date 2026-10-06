package templates

import (
	"html/template"
	"os"
	"path/filepath"

	"github.com/46labs/auth0/pkg/config"
)

type Loader struct {
	tmpl   *template.Template
	device *template.Template
}

// templateFuncs are the helpers the shipped login templates expect; a missing
// one fails template parsing at startup. Keep in step with templates/.
var templateFuncs = template.FuncMap{
	// (start, length, string), Sprig's argument order. Clamps rather than
	// panicking, and counts runes so a multi-byte initial stays whole.
	"substr": func(start, length int, s string) string {
		r := []rune(s)
		if start < 0 {
			start = 0
		}
		if start >= len(r) {
			return ""
		}
		end := start + length
		if length < 0 || end > len(r) {
			end = len(r)
		}
		return string(r[start:end])
	},
}

const defaultTemplate = `<!DOCTYPE html>
<html><head><title>{{.Branding.ServiceName}}</title></head>
<body><form method="post">
<input type="hidden" name="session_id" value="{{.SessionID}}">
<input name="identifier" placeholder="Email or SMS"{{if .LoginHint}} value="{{.LoginHint}}"{{end}}>
<input name="code" placeholder="Code">
<button type="submit">Sign In</button></form></body></html>`

const defaultDeviceTemplate = `<!DOCTYPE html>
<html><head><title>{{.Branding.ServiceName}}</title></head>
<body>{{if .Message}}<p>{{.Message}}</p>{{else if .UserCode}}<form method="POST" action="/device">
<p>{{.UserCode}} {{.ClientName}} {{.Audience}} {{.Scope}}</p>
<input type="hidden" name="user_code" value="{{.UserCode}}">
<input name="confirm_user_code" placeholder="Code shown on device">
<input name="identifier" placeholder="Email or SMS">
<input name="code" placeholder="Code">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button></form>{{else}}<form method="GET" action="/device">
<input name="user_code" placeholder="User code">
<button type="submit">Continue</button></form>{{end}}</body></html>`

// Each template resolves on its own: overriding the login page must not pin the
// device page to its fallback, or the reverse.
var (
	loginCandidates  = []string{"/config/login.html", "templates/default.html"}
	deviceCandidates = []string{"/config/device.html", "templates/device.html"}
)

func New(cfg *config.Config) (*Loader, error) {
	return newWithPaths(loginCandidates, deviceCandidates)
}

func newWithPaths(login, device []string) (*Loader, error) {
	loginTmpl, err := loadTemplate("default", login, defaultTemplate)
	if err != nil {
		return nil, err
	}
	deviceTmpl, err := loadTemplate("device", device, defaultDeviceTemplate)
	if err != nil {
		return nil, err
	}
	return &Loader{tmpl: loginTmpl, device: deviceTmpl}, nil
}

// NewFromFile parses a login template from disk, failing if it is missing; the
// device template resolves as it does in New.
func NewFromFile(path string) (*Loader, error) {
	loginTmpl, err := parseFile(path)
	if err != nil {
		return nil, err
	}
	deviceTmpl, err := loadTemplate("device", deviceCandidates, defaultDeviceTemplate)
	if err != nil {
		return nil, err
	}
	return &Loader{tmpl: loginTmpl, device: deviceTmpl}, nil
}

// loadTemplate parses the first candidate file that exists, else the inline
// fallback.
func loadTemplate(name string, candidates []string, inline string) (*template.Template, error) {
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		return parseFile(path)
	}
	return template.New(name).Funcs(templateFuncs).Parse(inline)
}

// parseFile names the template after the file because ParseFiles associates by
// base name and Execute resolves the created name.
func parseFile(path string) (*template.Template, error) {
	return template.New(filepath.Base(path)).Funcs(templateFuncs).ParseFiles(path)
}

func (l *Loader) Execute(w interface{ Write([]byte) (int, error) }, data interface{}) error {
	return l.tmpl.Execute(w, data)
}

func (l *Loader) ExecuteDevice(w interface{ Write([]byte) (int, error) }, data interface{}) error {
	return l.device.Execute(w, data)
}
