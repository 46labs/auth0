package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/46labs/auth0/pkg/config"
)

// dpopKey is a client's DPoP key pair.
type dpopKey struct{ priv *ecdsa.PrivateKey }

func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return dpopKey{k}
}

func (k dpopKey) jwk() map[string]any {
	b := func(n []byte) string { return base64.RawURLEncoding.EncodeToString(n) }
	pad := func(n []byte) []byte { return append(make([]byte, 32-len(n)), n...) }
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b(pad(k.priv.X.Bytes())), "y": b(pad(k.priv.Y.Bytes()))}
}

// thumbprint is the key's RFC 7638 SHA-256 thumbprint.
func (k dpopKey) thumbprint() string {
	j := k.jwk()
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + j["x"].(string) + `","y":"` + j["y"].(string) + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// proofOpts shape a proof: its method, URL, age, server nonce, the access
// token it is for, and a jwk header to send instead of the key's own.
type proofOpts struct {
	method, htu, nonce, token string
	iat                       time.Time
	jwk                       map[string]any
}

func (k dpopKey) proof(t *testing.T, o proofOpts) string {
	t.Helper()
	if o.method == "" {
		o.method = http.MethodPost
	}
	if o.iat.IsZero() {
		o.iat = time.Now()
	}
	claims := jwt.MapClaims{"jti": uuid.NewString(), "htm": o.method, "htu": o.htu, "iat": o.iat.Unix()}
	if o.nonce != "" {
		claims["nonce"] = o.nonce
	}
	if o.token != "" {
		sum := sha256.Sum256([]byte(o.token))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = k.jwk()
	if o.jwk != nil {
		tok.Header["jwk"] = o.jwk
	}
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type tokenReply struct {
	status int
	body   map[string]any
	nonce  string
}

func refreshWith(t *testing.T, tokenURL, refreshToken string, proofs ...string) tokenReply {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"test_client_actions"}, "refresh_token": {refreshToken},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return tokenReply{resp.StatusCode, out, resp.Header.Get("DPoP-Nonce")}
}

func jktOf(t *testing.T, token any) string {
	t.Helper()
	cnf, _ := claims(t, token)["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

func requireDPoP(c *config.Config) {
	c.ProofOfPossession = &config.ProofOfPossession{Mechanism: "dpop", Required: true}
}

// A confidential client: the proof binds both tokens, and every refresh
// needs a fresh proof from the same key.
func TestDPoP_RequiredBindsAccessAndRefreshTokens(t *testing.T) {
	srv, ts := setupTestServerWith(t, requireDPoP)
	defer ts.Close()
	tokenURL := srv.tokenEndpoint()
	scope := "openid profile email offline_access"
	key := newDPoPKey(t)

	if st, out := loginWithScope(t, ts, scope, ""); st != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Fatalf("a login without a proof: %d %v", st, out)
	}

	st, tok := loginWithHeader(t, ts, scope, "", func(string) http.Header {
		return http.Header{"Dpop": {key.proof(t, proofOpts{htu: tokenURL})}}
	})
	if st != http.StatusOK || tok["token_type"] != "DPoP" || jktOf(t, tok["access_token"]) != key.thumbprint() {
		t.Fatalf("a login with a proof: %d %v", st, tok)
	}
	rt, _ := tok["refresh_token"].(string)

	for name, proofs := range map[string][]string{
		"no proof":       nil,
		"another key":    {newDPoPKey(t).proof(t, proofOpts{htu: tokenURL})},
		"another htu":    {key.proof(t, proofOpts{htu: "https://elsewhere.test/oauth/token"})},
		"a stale proof":  {key.proof(t, proofOpts{htu: tokenURL, iat: time.Now().Add(-5 * time.Minute)})},
		"two proofs":     {key.proof(t, proofOpts{htu: tokenURL}), key.proof(t, proofOpts{htu: tokenURL})},
		"a private jwk":  {key.proof(t, proofOpts{htu: tokenURL, jwk: withPrivate(key)})},
		"another method": {key.proof(t, proofOpts{htu: tokenURL, method: http.MethodGet})},
	} {
		if r := refreshWith(t, tokenURL, rt, proofs...); r.status != http.StatusBadRequest {
			t.Fatalf("a bound refresh with %s: %d %v", name, r.status, r.body)
		}
	}
	proof := key.proof(t, proofOpts{htu: tokenURL})
	again := refreshWith(t, tokenURL, rt, proof)
	if again.status != http.StatusOK || again.body["token_type"] != "DPoP" || jktOf(t, again.body["access_token"]) != key.thumbprint() {
		t.Fatalf("a bound refresh with its key: %d %v", again.status, again.body)
	}
	next, _ := again.body["refresh_token"].(string)
	if next == "" {
		next = rt
	}
	if r := refreshWith(t, tokenURL, next, proof); r.status != http.StatusBadRequest {
		t.Fatalf("a replayed proof: %d %v", r.status, r.body)
	}
	if r := refreshWith(t, tokenURL, next); r.status != http.StatusBadRequest {
		t.Fatalf("the rotated token is bound too: %d %v", r.status, r.body)
	}
}

func withPrivate(k dpopKey) map[string]any {
	j := k.jwk()
	j["d"] = base64.RawURLEncoding.EncodeToString(k.priv.D.Bytes())
	return j
}

// A public client is challenged for the server's nonce first, keeps its code
// through the challenge, and refreshes with a nonce too.
func TestDPoP_PublicClientNonce(t *testing.T) {
	srv, ts := setupTestServerWith(t, func(c *config.Config) {
		requireDPoP(c)
		c.Clients = append(c.Clients, config.Client{
			ClientID: "test_client_actions", Name: "Native", AppType: "native",
			Callbacks:    []string{"http://localhost:3000/callback"},
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			RefreshToken: &config.RefreshTokenConfig{RotationType: config.RefreshTokenRotating},
		})
	})
	defer ts.Close()
	tokenURL := srv.tokenEndpoint()
	key := newDPoPKey(t)
	var asked []string
	st, tok := loginWithHeader(t, ts, "openid offline_access", "", func(nonce string) http.Header {
		asked = append(asked, nonce)
		return http.Header{"Dpop": {key.proof(t, proofOpts{htu: tokenURL, nonce: nonce})}}
	})
	if st != http.StatusOK || tok["token_type"] != "DPoP" {
		t.Fatalf("login: %d %v", st, tok)
	}
	if len(asked) != 2 || asked[0] != "" || asked[1] == "" {
		t.Fatalf("want a nonce challenge and one retry, got %q", asked)
	}
	rt, _ := tok["refresh_token"].(string)
	first := refreshWith(t, tokenURL, rt, key.proof(t, proofOpts{htu: tokenURL}))
	if first.status != http.StatusBadRequest || first.body["error"] != "use_dpop_nonce" || first.nonce == "" {
		t.Fatalf("a refresh without the nonce: %d %v", first.status, first.body)
	}
	if r := refreshWith(t, tokenURL, rt, key.proof(t, proofOpts{htu: tokenURL, nonce: first.nonce})); r.status != http.StatusOK {
		t.Fatalf("a refresh with the nonce: %d %v", r.status, r.body)
	}
}

// /userinfo takes a bound token only as DPoP with a proof for it.
func TestDPoP_UserInfo(t *testing.T) {
	srv, ts := setupTestServerWith(t, requireDPoP)
	defer ts.Close()
	key := newDPoPKey(t)
	_, tok := loginWithHeader(t, ts, "openid profile", "", func(string) http.Header {
		return http.Header{"Dpop": {key.proof(t, proofOpts{htu: srv.tokenEndpoint()})}}
	})
	access, _ := tok["access_token"].(string)
	get := func(scheme, proof string) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
		req.Header.Set("Authorization", scheme+" "+access)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	userinfo := srv.userInfoURL()
	if st := get("Bearer", ""); st != http.StatusUnauthorized {
		t.Fatalf("a bound token as bearer: %d", st)
	}
	if st := get("DPoP", key.proof(t, proofOpts{method: http.MethodGet, htu: userinfo, token: "other"})); st != http.StatusUnauthorized {
		t.Fatalf("a proof for another token: %d", st)
	}
	if st := get("DPoP", key.proof(t, proofOpts{method: http.MethodGet, htu: userinfo, token: access})); st != http.StatusOK {
		t.Fatalf("a proof for this token: %d", st)
	}
}

// An API without DPoP issues bearer tokens, a proof or not, and discovery
// advertises DPoP only when an API takes it.
func TestDPoP_OnlyWhereTheAPITakesIt(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()
	key := newDPoPKey(t)
	st, tok := loginWithHeader(t, ts, "openid", "", func(string) http.Header {
		return http.Header{"Dpop": {key.proof(t, proofOpts{htu: srv.tokenEndpoint()})}}
	})
	if st != http.StatusOK || tok["token_type"] != "Bearer" || jktOf(t, tok["access_token"]) != "" {
		t.Fatalf("%d %v", st, tok)
	}
	if srv.dpopEnabled() {
		t.Fatal("dpop enabled with no API taking it")
	}
}

// Discovery advertises DPoP's algorithms only when an API takes it, and a
// proof signed with another algorithm is refused.
func TestDPoP_AlgorithmsAdvertisedAndEnforced(t *testing.T) {
	discovery := func(url string) map[string]any {
		t.Helper()
		resp, err := http.Get(url + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		return doc
	}
	_, off := setupTestServer(t)
	defer off.Close()
	if _, ok := discovery(off.URL)["dpop_signing_alg_values_supported"]; ok {
		t.Fatal("advertised without an API taking DPoP")
	}
	srv, on := setupTestServerWith(t, requireDPoP)
	defer on.Close()
	if algs, _ := discovery(on.URL)["dpop_signing_alg_values_supported"].([]any); len(algs) != 1 || algs[0] != "ES256" {
		t.Fatalf("algs %v", algs)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := func(n []byte) string { return base64.RawURLEncoding.EncodeToString(n) }
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"jti": uuid.NewString(), "htm": http.MethodPost, "htu": srv.tokenEndpoint(), "iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]any{"kty": "RSA", "n": b(rsaKey.N.Bytes()), "e": b(big.NewInt(int64(rsaKey.E)).Bytes())}
	proof, err := tok.SignedString(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	st, out := loginWithHeader(t, on, "openid", "", func(string) http.Header { return http.Header{"Dpop": {proof}} })
	if st != http.StatusBadRequest || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("an RS256 proof: %d %v", st, out)
	}
}
