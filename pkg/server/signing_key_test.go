package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	jwtmwv2 "github.com/auth0/go-jwt-middleware/v2/jwks"
	validatorv2 "github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dop251/goja"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/46labs/auth0/pkg/config"
)

const (
	tenantAudience = "https://api.example.test"
	m2mClient      = "m2m_client"
	m2mSecret      = "m2m_secret"
)

// tenant serves one issuer URL whose Server can be replaced, which is what a
// pod restart looks like to a verifier that has already cached the key set.
type tenant struct {
	t       *testing.T
	ts      *httptest.Server
	handler atomic.Pointer[http.Handler]
	keyFile string
	srv     *Server
}

func newTenant(t *testing.T, keyFile string) *tenant {
	t.Helper()
	tn := &tenant{t: t, keyFile: keyFile}
	tn.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*tn.handler.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(tn.ts.Close)
	tn.restart()
	return tn
}

func (tn *tenant) issuer() string { return tn.ts.URL + "/" }

// restart replaces the Server behind the issuer, as a new pod would: a fresh
// config and fresh in-memory state.
func (tn *tenant) restart() {
	tn.t.Helper()
	srv, err := New(&config.Config{
		Issuer:         tn.issuer(),
		Audience:       tenantAudience,
		CORSOrigins:    []string{"*"},
		SigningKeyFile: tn.keyFile,
		Clients: []config.Client{{
			ClientID:     m2mClient,
			ClientSecret: m2mSecret,
			AppType:      "non_interactive",
			GrantTypes:   []string{"client_credentials"},
		}},
	})
	if err != nil {
		tn.t.Fatalf("New: %v", err)
	}
	h := srv.Handler()
	tn.handler.Store(&h)
	tn.srv = srv
}

// token is an access token from the mock's token endpoint, through the
// standard OAuth2 client.
func (tn *tenant) token() string {
	tn.t.Helper()
	cc := clientcredentials.Config{
		ClientID:       m2mClient,
		ClientSecret:   m2mSecret,
		TokenURL:       tn.ts.URL + "/oauth/token",
		EndpointParams: url.Values{"audience": {tenantAudience}},
		AuthStyle:      oauth2.AuthStyleInParams,
	}
	tok, err := cc.Token(context.Background())
	if err != nil {
		tn.t.Fatalf("client credentials: %v", err)
	}
	return tok.AccessToken
}

func writeKey(t *testing.T, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rsaKeyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeKey(t, "PRIVATE KEY", der)
}

// rfc7638 computes the thumbprint by hand, independent of go-jose.
func rfc7638(pub *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	sum := sha256.Sum256([]byte(fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func headerKID(t *testing.T, token string) string {
	t.Helper()
	tok, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	kid, _ := tok.Header["kid"].(string)
	return kid
}

func TestSigningKeyKIDIsThumbprint(t *testing.T) {
	tn := newTenant(t, "")

	resp, err := http.Get(tn.ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	jwk := set.Keys[0]
	want := rfc7638(&tn.srv.privateKey.PublicKey)
	for field, v := range map[string]string{"kid": want, "kty": "RSA", "alg": "RS256", "use": "sig"} {
		if jwk[field] != v {
			t.Errorf("jwks %s = %q, want %q", field, jwk[field], v)
		}
	}
	if got := headerKID(t, tn.token()); got != want {
		t.Errorf("token kid = %q, want %q", got, want)
	}
}

// Auth0 serves its key set with this header; verifiers that refresh on a
// timer read max-age from it.
func TestJWKSCacheControlMatchesAuth0(t *testing.T) {
	tn := newTenant(t, "")
	resp, err := http.Get(tn.ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	want := "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"
	if got := resp.Header.Get("Cache-Control"); got != want {
		t.Errorf("Cache-Control = %q, want %q", got, want)
	}
}

func TestSigningKeyFile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	formats := map[string]string{
		"PKCS#1": writeKey(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
		"PKCS#8": writeKey(t, "PRIVATE KEY", pkcs8),
	}
	for name, path := range formats {
		t.Run(name, func(t *testing.T) {
			k, err := loadSigningKey(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if !k.private.Equal(key) {
				t.Error("loaded a different key")
			}
			if k.kid != rfc7638(&key.PublicKey) {
				t.Errorf("kid = %q, want the thumbprint", k.kid)
			}
		})
	}

	t.Run("generated keys differ", func(t *testing.T) {
		a, err := loadSigningKey("")
		if err != nil {
			t.Fatal(err)
		}
		b, err := loadSigningKey("")
		if err != nil {
			t.Fatal(err)
		}
		if a.kid == b.kid {
			t.Error("two generated keys share a kid")
		}
	})
}

func TestSigningKeyFileRejected(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"missing":     filepath.Join(t.TempDir(), "absent.pem"),
		"not PEM":     garbage,
		"EC key":      writeKey(t, "PRIVATE KEY", ecDER),
		"public only": writeKey(t, "PUBLIC KEY", pubDER),
		"bad PKCS#1":  writeKey(t, "RSA PRIVATE KEY", []byte("junk")),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(&config.Config{Issuer: "https://auth.example.test/", SigningKeyFile: path}); err == nil {
				t.Fatal("New started with an unusable signing key file")
			}
		})
	}
}

// Actions verify with jwks-rsa's getSigningKey(kid); the retired fixed kid
// must not resolve any more.
func TestActionsSigningKeyByKID(t *testing.T) {
	tn := newTenant(t, "")
	vm := goja.New()
	if _, err := tn.srv.signingKey(vm, tn.srv.jwksURI(), tn.srv.kid); err != nil {
		t.Errorf("current kid: %v", err)
	}
	if _, err := tn.srv.signingKey(vm, tn.srv.jwksURI(), "key-1"); err == nil {
		t.Error("the retired fixed kid key-1 still resolves")
	}
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, within time.Duration, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(within)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		err := cond()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: %v", within, err)
		}
		<-tick.C
	}
}

// The scenarios below run Auth0's own API SDK, go-jwt-middleware, against a
// restarting mock: v3 is current, v2 is what PEE runs.

func sdkV3(t *testing.T, tn *tenant) *validator.Validator {
	t.Helper()
	u, err := url.Parse(tn.issuer())
	if err != nil {
		t.Fatal(err)
	}
	p, err := jwks.NewCachingProvider(jwks.WithIssuerURL(u))
	if err != nil {
		t.Fatalf("caching provider: %v", err)
	}
	v, err := validator.New(
		validator.WithKeyFunc(p.KeyFunc),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuer(tn.issuer()),
		validator.WithAudience(tenantAudience),
	)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	return v
}

func sdkV2(t *testing.T, tn *tenant) *validatorv2.Validator {
	t.Helper()
	u, err := url.Parse(tn.issuer())
	if err != nil {
		t.Fatal(err)
	}
	// PEE's setting.
	p := jwtmwv2.NewCachingProvider(u, 5*time.Minute)
	v, err := validatorv2.New(p.KeyFunc, validatorv2.RS256, tn.issuer(), []string{tenantAudience})
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	return v
}

func TestSDKAcrossRestart(t *testing.T) {
	ctx := context.Background()

	// A configured key survives a restart: the cached key set still matches,
	// and tokens issued before the restart stay valid.
	t.Run("v3 configured key", func(t *testing.T) {
		t.Parallel()
		tn := newTenant(t, rsaKeyFile(t))
		v := sdkV3(t, tn)
		before := tn.token()
		if _, err := v.ValidateToken(ctx, before); err != nil {
			t.Fatalf("before restart: %v", err)
		}
		kid := tn.srv.kid
		tn.restart()
		if tn.srv.kid != kid {
			t.Fatalf("kid changed across restart with a configured key")
		}
		if _, err := v.ValidateToken(ctx, tn.token()); err != nil {
			t.Errorf("token after restart: %v", err)
		}
		if _, err := v.ValidateToken(ctx, before); err != nil {
			t.Errorf("token from before restart: %v", err)
		}
	})

	t.Run("v2 configured key", func(t *testing.T) {
		t.Parallel()
		tn := newTenant(t, rsaKeyFile(t))
		v := sdkV2(t, tn)
		if _, err := v.ValidateToken(ctx, tn.token()); err != nil {
			t.Fatalf("before restart: %v", err)
		}
		tn.restart()
		if _, err := v.ValidateToken(ctx, tn.token()); err != nil {
			t.Errorf("token after restart: %v", err)
		}
	})

	// A generated key changes at restart. v3 honours the key set's max-age,
	// so it picks up the new key within Auth0's 15 seconds instead of its
	// own 15-minute default. The SDK's cache reads the wall clock and takes no
	// injected time, so this polls for about 12 seconds; -short skips it.
	t.Run("v3 generated key", func(t *testing.T) {
		if testing.Short() {
			t.Skip("waits out the SDK's real JWKS refresh")
		}
		t.Parallel()
		tn := newTenant(t, "")
		v := sdkV3(t, tn)
		if _, err := v.ValidateToken(ctx, tn.token()); err != nil {
			t.Fatalf("before restart: %v", err)
		}
		kid := tn.srv.kid
		tn.restart()
		if tn.srv.kid == kid {
			t.Fatal("a generated key kept its kid across restart")
		}
		after := tn.token()
		eventually(t, 30*time.Second, func() error {
			_, err := v.ValidateToken(ctx, after)
			return err
		})
	})

	// go-oidc, PEE's other verifier, refetches the key set when no cached key
	// verifies, so it accepts the new key at once.
	t.Run("go-oidc generated key", func(t *testing.T) {
		t.Parallel()
		tn := newTenant(t, "")
		ks := oidc.NewRemoteKeySet(ctx, tn.ts.URL+"/.well-known/jwks.json")
		v := oidc.NewVerifier(tn.issuer(), ks, &oidc.Config{SkipClientIDCheck: true})
		if _, err := v.Verify(ctx, tn.token()); err != nil {
			t.Fatalf("before restart: %v", err)
		}
		tn.restart()
		if _, err := v.Verify(ctx, tn.token()); err != nil {
			t.Errorf("after restart: %v", err)
		}
	})
}
