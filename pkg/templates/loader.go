package templates

import (
	"html/template"
	"os"

	"github.com/46labs/auth0/pkg/config"
)

type Loader struct {
	tmpl *template.Template
}

const defaultTemplate = `<!DOCTYPE html>
<html><head><title>{{.Branding.ServiceName}}</title></head>
<body><form method="post">
<input type="hidden" name="session_id" value="{{.SessionID}}">
<input name="phone" placeholder="Phone"><input name="code" placeholder="Code">
<button type="submit">Sign In</button></form></body></html>`

func New(cfg *config.Config) (*Loader, error) {
	var tmpl *template.Template
	var err error

	if _, err := os.Stat("/config/login.html"); err == nil {
		tmpl, err = template.ParseFiles("/config/login.html")
	} else if _, err := os.Stat("templates/default.html"); err == nil {
		tmpl, err = template.ParseFiles("templates/default.html")
	} else {
		tmpl, err = template.New("default").Parse(defaultTemplate)
	}

	if err != nil {
		return nil, err
	}

	return &Loader{tmpl: tmpl}, nil
}

func (l *Loader) Execute(w interface{ Write([]byte) (int, error) }, data interface{}) error {
	return l.tmpl.Execute(w, data)
}
