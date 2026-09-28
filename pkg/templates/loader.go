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
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{.Branding.ServiceName}} - Device authorization</title>
<style>body{font-family:system-ui,sans-serif;background:#111;color:#fff;display:flex;justify-content:center;padding:48px 16px}.panel{width:100%;max-width:480px;background:#202225;border:1px solid #4d5d70;border-radius:8px;padding:32px}h1{margin-top:0}dt{color:#aeb6c2;margin-top:16px}dd{margin:4px 0 0;word-break:break-word}.code{font-size:1.6rem;letter-spacing:.15em;font-weight:700}.error{color:#ffb4ab}.actions{display:flex;gap:12px;margin-top:24px}button{border:0;border-radius:6px;padding:12px 18px;font-weight:600;cursor:pointer}button[name=decision][value=approve]{background:{{if .Branding.PrimaryColor}}{{.Branding.PrimaryColor}}{{else}}#3b82f6{{end}};color:#111}button[name=decision][value=deny]{background:#4d3030;color:#fff}input{width:100%;box-sizing:border-box;padding:12px;margin-top:8px;background:#111;color:#fff;border:1px solid #4d5d70;border-radius:6px}</style></head>
<body><main class="panel"><h1>Authorize this device</h1>{{if .Message}}<p>{{.Message}}</p>{{else}}{{if .UserCode}}<p>Confirm the code shown on your device before continuing.</p><dl><dt>Code</dt><dd class="code">{{.UserCode}}</dd><dt>Application</dt><dd>{{.ClientName}}</dd><dt>Audience</dt><dd>{{.Audience}}</dd><dt>Requested scopes</dt><dd>{{.Scope}}</dd></dl><form method="post" action="/device"><input type="hidden" name="user_code" value="{{.UserCode}}"><label>Re-enter the code<input name="confirm_user_code" autocomplete="off" required></label><label>Local user identifier<input name="identifier" placeholder="Email or SMS" autocomplete="username" required></label><label>Verification code<input name="code" inputmode="numeric" required></label><div class="actions"><button type="submit" name="decision" value="approve">Approve</button><button type="submit" name="decision" value="deny">Deny</button></div></form>{{else}}<p>Enter the code shown on your device.</p><form method="get" action="/device"><label>User code<input name="user_code" autocomplete="off" required></label><div class="actions"><button type="submit">Continue</button></div></form>{{end}}{{end}}</main></body></html>`

func New(cfg *config.Config) (*Loader, error) {
	for _, path := range []string{"/config/login.html", "templates/default.html"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		return NewFromFile(path)
	}

	tmpl, err := template.New("default").Funcs(templateFuncs).Parse(defaultTemplate)
	if err != nil {
		return nil, err
	}
	device, err := template.New("device").Funcs(templateFuncs).Parse(defaultDeviceTemplate)
	if err != nil {
		return nil, err
	}
	return &Loader{tmpl: tmpl, device: device}, nil
}

// NewFromFile parses a login template from disk, named after the file because
// ParseFiles associates by base name and Execute resolves the created name.
func NewFromFile(path string) (*Loader, error) {
	tmpl, err := template.New(filepath.Base(path)).Funcs(templateFuncs).ParseFiles(path)
	if err != nil {
		return nil, err
	}
	device, err := template.New("device").Funcs(templateFuncs).Parse(defaultDeviceTemplate)
	if err != nil {
		return nil, err
	}
	return &Loader{tmpl: tmpl, device: device}, nil
}

func (l *Loader) Execute(w interface{ Write([]byte) (int, error) }, data interface{}) error {
	return l.tmpl.Execute(w, data)
}

func (l *Loader) ExecuteDevice(w interface{ Write([]byte) (int, error) }, data interface{}) error {
	return l.device.Execute(w, data)
}
