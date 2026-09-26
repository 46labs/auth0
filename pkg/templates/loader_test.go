package templates

import (
	"strings"
	"testing"

	"github.com/46labs/auth0/pkg/config"
)

// TestShippedTemplateParsesAndRenders is the test whose absence let the binary
// ship unable to start: templates/default.html calls substr, which was not
// registered, so template parsing failed at startup. The unit tests never
// caught it because they run with a working directory where that file is not
// found and the inline fallback is used instead.
func TestShippedTemplateParsesAndRenders(t *testing.T) {
	loader, err := NewFromFile("../../templates/default.html")
	if err != nil {
		t.Fatalf("the shipped login template must parse: %v", err)
	}

	var out strings.Builder
	err = loader.Execute(&out, map[string]any{
		"SessionID": "sess_1",
		"LoginHint": "user@example.test",
		"Branding": config.Branding{
			ServiceName:  "Nextel",
			PrimaryColor: "#FFD100",
			Title:        "Welcome",
			Subtitle:     "Sign in",
		},
	})
	if err != nil {
		t.Fatalf("the shipped login template must render: %v", err)
	}

	rendered := out.String()
	if rendered == "" {
		t.Fatal("rendered an empty page")
	}
	// Named-template resolution: ParseFiles associates by base name, so a
	// mismatched template name renders nothing at all.
	if !strings.Contains(rendered, "sess_1") {
		t.Error("session id not rendered; template name likely mismatched")
	}
	if !strings.Contains(rendered, "user@example.test") {
		t.Error("login hint not rendered")
	}
	// substr 0 1 "Nextel" is the logo initial.
	if !strings.Contains(rendered, ">N<") {
		t.Error("substr-derived logo initial not rendered")
	}
}

// TestNewFallsBackToInlineTemplate covers the path the tests themselves run
// on, where no template file is present.
func TestNewFallsBackToInlineTemplate(t *testing.T) {
	loader, err := New(&config.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var out strings.Builder
	if err := loader.Execute(&out, map[string]any{
		"SessionID": "sess_2",
		"Branding":  config.Branding{ServiceName: "Fallback"},
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "sess_2") {
		t.Errorf("inline fallback did not render the session id: %s", out.String())
	}
}

func TestSubstr(t *testing.T) {
	substr := templateFuncs["substr"].(func(int, int, string) string)

	tests := []struct {
		name          string
		start, length int
		in            string
		want          string
	}{
		{"logo initial", 0, 1, "Nextel", "N"},
		{"whole string", 0, 6, "Nextel", "Nextel"},
		{"middle", 2, 3, "Nextel", "xte"},
		{"length past end clamps", 3, 99, "Nextel", "tel"},
		{"start past end is empty", 99, 1, "Nextel", ""},
		{"empty input", 0, 1, "", ""},
		{"negative start clamps to zero", -5, 2, "Nextel", "Ne"},
		{"negative length runs to end", 2, -1, "Nextel", "xtel"},
		{"multi-byte initial stays whole", 0, 1, "Ätna", "Ä"},
		{"emoji initial stays whole", 0, 1, "🔒Secure", "🔒"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := substr(tc.start, tc.length, tc.in); got != tc.want {
				t.Errorf("substr(%d, %d, %q) = %q, want %q", tc.start, tc.length, tc.in, got, tc.want)
			}
		})
	}
}
