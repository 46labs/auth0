package config_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/46labs/auth0/pkg/config"
	"github.com/spf13/viper"
)

// TestChartRendersLoadableConfig renders the chart the way a consumer deploys
// it and loads the result through the real loader.
//
// Rendering alone proves nothing: the chart shipped a config that rendered
// fine and could not be parsed (`corsOrigins: - *` is invalid YAML), and one
// whose user key did not match the mapstructure tag, so the fixture user
// loaded with an empty id. Both were invisible until something loaded it.
func TestChartRendersLoadableConfig(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}

	chart := filepath.Join("..", "..", "charts", "auth0")
	if _, err := os.Stat(chart); err != nil {
		t.Skipf("chart not found: %v", err)
	}

	cases := map[string]string{
		// Defaults are what someone gets with `helm install` and no values.
		"defaults": "",
		// And the shape the onboarding flow needs: an enterprise connection
		// with auto-membership, plus a client carrying a login URI.
		"invitation prerequisites": `
config:
  organizations:
    - id: org_acme
      name: acme
  connections:
    - id: con_sso
      name: enterprise-sso
      strategy: oidc
      organizations: ["org_acme"]
  roles:
    - id: rol_admin
      name: admin
  organizationConnections:
    - org_id: org_acme
      connection_id: con_sso
      assign_membership_on_login: true
  clients:
    - client_id: peeredge_web
      name: PeerEdge Web
      app_type: spa
      initiate_login_uri: https://peeredge.test/login
`,
	}

	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			args := []string{"template", "t", chart}
			if values != "" {
				f := filepath.Join(t.TempDir(), "values.yaml")
				if err := os.WriteFile(f, []byte(values), 0o644); err != nil {
					t.Fatalf("write values: %v", err)
				}
				args = append(args, "-f", f)
			}

			out, err := exec.Command(helm, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}

			rendered := extractConfigYAML(t, string(out))
			cfg := loadFrom(t, rendered)

			if cfg.Issuer == "" {
				t.Error("issuer did not load")
			}
			if len(cfg.CORSOrigins) == 0 {
				t.Error("corsOrigins did not load")
			}
			if len(cfg.Users) == 0 {
				t.Fatal("users did not load")
			}
			for i, u := range cfg.Users {
				if u.ID == "" {
					t.Errorf("user %d loaded with an empty id: %+v", i, u)
				}
			}
		})
	}
}

// TestChartInvitationPrerequisitesLoad checks the specific fields the
// invitation flow refuses to work without.
func TestChartInvitationPrerequisitesLoad(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	chart := filepath.Join("..", "..", "charts", "auth0")

	values := `
config:
  organizations:
    - id: org_acme
      name: acme
  connections:
    - id: con_sso
      name: enterprise-sso
      strategy: oidc
      organizations: ["org_acme"]
  organizationConnections:
    - org_id: org_acme
      connection_id: con_sso
      assign_membership_on_login: true
  clients:
    - client_id: peeredge_web
      name: PeerEdge Web
      app_type: spa
      initiate_login_uri: https://peeredge.test/login
`
	f := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(f, []byte(values), 0o644); err != nil {
		t.Fatalf("write values: %v", err)
	}
	out, err := exec.Command(helm, "template", "t", chart, "-f", f).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cfg := loadFrom(t, extractConfigYAML(t, string(out)))

	if len(cfg.Clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(cfg.Clients))
	}
	if got := cfg.Clients[0].InitiateLoginURI; got != "https://peeredge.test/login" {
		t.Errorf("initiate_login_uri = %q; without it invitation create 400s", got)
	}

	var nonPasswordless bool
	for i := range cfg.Connections {
		if !cfg.Connections[i].IsPasswordless() {
			nonPasswordless = true
		}
	}
	if !nonPasswordless {
		t.Error("no non-passwordless connection loaded; invitations reject passwordless")
	}

	if len(cfg.OrganizationConnections) != 1 {
		t.Fatalf("expected 1 pairing, got %d", len(cfg.OrganizationConnections))
	}
	if !cfg.OrganizationConnections[0].AssignMembershipOnLogin {
		t.Error("assign_membership_on_login did not load; the OIN self-serve path needs it")
	}
}

// TestChartMountsCustomTemplates checks each custom page gets its own
// ConfigMap and mount, and that enabling one never drags in the other.
func TestChartMountsCustomTemplates(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	chart := filepath.Join("..", "..", "charts", "auth0")

	login := []string{"mountPath: /config/login.html", "name: t-auth0-login", "LOGIN_MARKER"}
	device := []string{"mountPath: /config/device.html", "name: t-auth0-device", "DEVICE_MARKER"}

	tests := []struct {
		name              string
		loginOn, deviceOn bool
	}{
		{"neither", false, false},
		{"login only", true, false},
		{"device only", false, true},
		{"both", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"template", "t", chart,
				"--set", fmt.Sprintf("customLogin.enabled=%t", tc.loginOn),
				"--set-string", "customLogin.html=<p>LOGIN_MARKER {{.SessionID}}</p>",
				"--set", fmt.Sprintf("customDevice.enabled=%t", tc.deviceOn),
				"--set-string", "customDevice.html=<p>DEVICE_MARKER {{.UserCode}}</p>",
			}
			out, err := exec.Command(helm, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			rendered := string(out)
			for _, want := range login {
				if strings.Contains(rendered, want) != tc.loginOn {
					t.Errorf("login enabled=%t, but %q present=%t", tc.loginOn, want, !tc.loginOn)
				}
			}
			for _, want := range device {
				if strings.Contains(rendered, want) != tc.deviceOn {
					t.Errorf("device enabled=%t, but %q present=%t", tc.deviceOn, want, !tc.deviceOn)
				}
			}
		})
	}
}

// TestChartSigningKey checks the signing key Secret is mounted where the
// rendered config points, and that nothing is mounted without one.
func TestChartSigningKey(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	chart := filepath.Join("..", "..", "charts", "auth0")

	t.Run("configured", func(t *testing.T) {
		out, err := exec.Command(helm, "template", "t", chart,
			"--set", "signingKey.secretName=auth0-signing").CombinedOutput()
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cfg := loadFrom(t, extractConfigYAML(t, string(out)))
		if cfg.SigningKeyFile != "/config/signing-key/tls.key" {
			t.Errorf("SigningKeyFile = %q", cfg.SigningKeyFile)
		}
		for _, want := range []string{"mountPath: /config/signing-key", "secretName: auth0-signing", `key: "tls.key"`} {
			if !strings.Contains(string(out), want) {
				t.Errorf("rendered chart lacks %q", want)
			}
		}
		volume := string(out)[strings.Index(string(out), "- name: signing-key\n        secret:"):]
		if end := strings.Index(volume[1:], "- name:"); end != -1 {
			volume = volume[:end+1]
		}
		if strings.Contains(volume, "optional: true") {
			t.Errorf("signing key Secret is optional; the mock would start with a throwaway key:\n%s", volume)
		}
	})

	t.Run("unset", func(t *testing.T) {
		out, err := exec.Command(helm, "template", "t", chart).CombinedOutput()
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		if strings.Contains(string(out), "signing-key") {
			t.Error("signing key mounted without a Secret")
		}
		if cfg := loadFrom(t, extractConfigYAML(t, string(out))); cfg.SigningKeyFile != "" {
			t.Errorf("SigningKeyFile = %q, want empty", cfg.SigningKeyFile)
		}
	})
}

func TestSigningKeyFileFromEnv(t *testing.T) {
	t.Setenv("SIGNING_KEY_FILE", "/keys/tls.key")
	if cfg := loadFrom(t, "issuer: https://auth.example.test/\n"); cfg.SigningKeyFile != "/keys/tls.key" {
		t.Errorf("SigningKeyFile = %q, want the SIGNING_KEY_FILE value", cfg.SigningKeyFile)
	}
}

func TestDeviceCodeLifetimeLoadsAsDuration(t *testing.T) {
	cfg := loadFrom(t, "deviceCodeLifetime: 2s\n")
	if cfg.DeviceCodeLifetime != 2*time.Second {
		t.Fatalf("DeviceCodeLifetime = %s, want 2s", cfg.DeviceCodeLifetime)
	}
}

// extractConfigYAML pulls the config.yaml value out of the rendered ConfigMap.
func extractConfigYAML(t *testing.T, rendered string) string {
	t.Helper()

	const key = "config.yaml: |"
	idx := strings.Index(rendered, key)
	if idx == -1 {
		t.Fatal("no config.yaml in the rendered chart")
	}

	var out []string
	for _, line := range strings.Split(rendered[idx+len(key):], "\n")[1:] {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "    ") {
			break
		}
		out = append(out, strings.TrimPrefix(line, "    "))
	}
	return strings.Join(out, "\n") + "\n"
}

// loadFrom writes the config where the loader looks and loads it.
func loadFrom(t *testing.T, body string) *config.Config {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigFile(path)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("the chart rendered a config the loader rejects: %v\n---\n%s", err, body)
	}
	return cfg
}

// A seeded client's refresh_token loads whole from YAML, policies included.
func TestRefreshTokenLoadsFromYAML(t *testing.T) {
	cfg := loadFrom(t, `
clients:
  - client_id: seeded
    name: Seeded
    refresh_token:
      rotation_type: rotating
      leeway: 30
      token_lifetime: 3600
      policies:
        - audience: https://api.test
          scope: [read:things]
`)
	rt := cfg.Clients[0].RefreshToken
	if rt == nil || rt.RotationType != "rotating" || rt.Leeway != 30 || rt.TokenLifetime == nil || *rt.TokenLifetime != 3600 {
		t.Fatalf("refresh_token = %+v", rt)
	}
	if len(rt.Policies) != 1 || rt.Policies[0].Audience != "https://api.test" || !slices.Equal(rt.Policies[0].Scope, []string{"read:things"}) {
		t.Fatalf("policies = %+v", rt.Policies)
	}
}

func TestDeployedActionsLoadFromYAML(t *testing.T) {
	cfg := loadFrom(t, `
actions:
  deployed:
    - name: Role claim
      code: |
        exports.onExecutePostLogin = async (event, api) => {
          api.accessToken.setCustomClaim("https://example.test/role", "admin");
        };
      secrets:
        - name: API
          value: https://api.test
`)
	d := cfg.Actions.Deployed
	if len(d) != 1 || d[0].Name != "Role claim" || d[0].Trigger != "" || len(d[0].Secrets) != 1 || d[0].Secrets[0] != (config.ActionSecret{Name: "API", Value: "https://api.test"}) {
		t.Fatalf("deployed = %+v", d)
	}
	if !strings.Contains(d[0].Code, "setCustomClaim(\"https://example.test/role\"") || !strings.HasSuffix(d[0].Code, "};\n") {
		t.Fatalf("code = %q", d[0].Code)
	}
}
