package templates

import (
	"html/template"
	"os"
	"path/filepath"

	"github.com/46labs/auth0/pkg/config"
)

type Loader struct {
	tmpl *template.Template
}

// templateFuncs are the helpers the shipped login templates expect. Without
// them template parsing fails at startup, which is not something the server
// can recover from, so keep this in step with templates/default.html.
var templateFuncs = template.FuncMap{
	// substr takes (start, length, string) in Sprig's argument order, which is
	// what the templates were written against. Bounds are clamped rather than
	// panicking mid-render, and it counts runes so a multi-byte initial is not
	// split in half.
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
	return &Loader{tmpl: tmpl}, nil
}

// NewFromFile parses a login template from disk. The template is named after
// the file because ParseFiles associates parsed templates by base name, and
// Execute resolves the name the template was created with.
func NewFromFile(path string) (*Loader, error) {
	tmpl, err := template.New(filepath.Base(path)).Funcs(templateFuncs).ParseFiles(path)
	if err != nil {
		return nil, err
	}
	return &Loader{tmpl: tmpl}, nil
}

func (l *Loader) Execute(w interface{ Write([]byte) (int, error) }, data interface{}) error {
	return l.tmpl.Execute(w, data)
}
