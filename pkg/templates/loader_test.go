package templates

import (
	"os"
	"path/filepath"
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

	for _, state := range deviceStates {
		t.Run("device "+state.name, func(t *testing.T) {
			var page strings.Builder
			if err := loader.ExecuteDevice(&page, state.data); err != nil {
				t.Fatalf("ExecuteDevice: %v", err)
			}
			assertContainsAll(t, page.String(), state.want)
		})
	}
}

// deviceFormFields are the names handleDeviceVerification reads. A device
// template that renames one breaks approval without failing to render.
var deviceFormFields = []string{
	`name="user_code"`,
	`name="confirm_user_code"`,
	`name="identifier"`,
	`name="code"`,
	`name="decision" value="approve"`,
	`name="decision" value="deny"`,
}

var deviceStates = []struct {
	name string
	data map[string]any
	want []string
}{
	{
		name: "entry",
		data: map[string]any{"Branding": testBranding},
		want: []string{`method="GET" action="/device"`, `name="user_code"`},
	},
	{
		name: "confirm",
		data: map[string]any{
			"Branding":   testBranding,
			"UserCode":   "BCDF-GHJK",
			"ClientName": "Dev Device Client",
			"Audience":   "https://api.example.test",
			"Scope":      "openid offline_access",
		},
		want: append([]string{
			`method="POST" action="/device"`,
			"BCDF-GHJK", "Dev Device Client", "https://api.example.test", "openid offline_access",
		}, deviceFormFields...),
	},
	{
		name: "result",
		data: map[string]any{"Branding": testBranding, "Message": "Device authorization approved."},
		want: []string{"Device authorization approved."},
	},
}

var testBranding = config.Branding{
	ServiceName:  "Nextel",
	PrimaryColor: "#FFD100",
	Title:        "Welcome",
	Subtitle:     "Sign in",
}

func assertContainsAll(t *testing.T, page string, want []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(page, w) {
			t.Errorf("rendered page is missing %q", w)
		}
	}
}

// TestShippedDeviceTemplateParsesAndRenders is the device counterpart of
// TestShippedTemplateParsesAndRenders: the shipped file is only parsed when
// the process runs from the repo root, so nothing else exercises it.
func TestShippedDeviceTemplateParsesAndRenders(t *testing.T) {
	loader, err := newWithPaths(nil, []string{"../../templates/device.html"})
	if err != nil {
		t.Fatalf("the shipped device template must parse: %v", err)
	}
	if name := loader.device.Name(); name != "device.html" {
		t.Fatalf("device template = %q, want the shipped device.html", name)
	}

	for _, state := range deviceStates {
		t.Run(state.name, func(t *testing.T) {
			var out strings.Builder
			if err := loader.ExecuteDevice(&out, state.data); err != nil {
				t.Fatalf("the shipped device template must render: %v", err)
			}
			// Branding reaches the page the same way it does on login:
			// substr-derived logo initial, title and subtitle.
			assertContainsAll(t, out.String(), append([]string{">N<", "Welcome", "Sign in"}, state.want...))
		})
	}
}

// TestTemplatesResolveIndependently pins the bug where a mounted login
// template returned early and forced the inline device page, so a custom
// device page could never load alongside a custom login page.
func TestTemplatesResolveIndependently(t *testing.T) {
	dir := t.TempDir()
	login := filepath.Join(dir, "login.html")
	device := filepath.Join(dir, "device.html")
	missing := filepath.Join(dir, "missing.html")
	if err := os.WriteFile(login, []byte(`custom login {{.SessionID}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(device, []byte(`custom device {{.UserCode}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name               string
		login, device      string
		wantLogin, wantDev string
	}{
		{"both custom", login, device, "custom login", "custom device"},
		{"custom login only", login, missing, "custom login", `name="user_code"`},
		{"custom device only", missing, device, `name="session_id"`, "custom device"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			loader, err := newWithPaths([]string{tc.login}, []string{tc.device})
			if err != nil {
				t.Fatalf("newWithPaths: %v", err)
			}
			var loginOut, deviceOut strings.Builder
			if err := loader.Execute(&loginOut, map[string]any{"SessionID": "s", "Branding": testBranding}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if err := loader.ExecuteDevice(&deviceOut, map[string]any{"UserCode": "BCDF-GHJK", "Branding": testBranding}); err != nil {
				t.Fatalf("ExecuteDevice: %v", err)
			}
			if !strings.Contains(loginOut.String(), tc.wantLogin) {
				t.Errorf("login page = %q, want %q", loginOut.String(), tc.wantLogin)
			}
			if !strings.Contains(deviceOut.String(), tc.wantDev) {
				t.Errorf("device page = %q, want %q", deviceOut.String(), tc.wantDev)
			}
		})
	}
}

func TestNewFromFileRequiresTheFile(t *testing.T) {
	if _, err := NewFromFile(filepath.Join(t.TempDir(), "missing.html")); err == nil {
		t.Fatal("NewFromFile on a missing path must fail, not fall back to the inline page")
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
