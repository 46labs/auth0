package config_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
