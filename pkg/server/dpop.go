package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/golang-jwt/jwt/v5"

	"github.com/46labs/auth0/pkg/config"
)

// DPoP (RFC 9449), as Auth0 does it. A valid proof on a token request binds
// the refresh token to the proof's key, and the access token too (cnf.jkt,
// token_type DPoP) when the API's proof_of_possession mechanism is dpop. A
// refresh of a bound token needs a proof from the same key. A public client
// (spa, native) must put the server's DPoP-Nonce in its proof: the first
// proof is answered use_dpop_nonce with the nonce to retry with. An API that
// requires DPoP refuses a request without a proof.

const (
	dpopHeader      = "DPoP"
	dpopNonceHeader = "DPoP-Nonce"
	// dpopProofWindow is how far a proof's iat may be from now.
	dpopProofWindow = 60 * time.Second
	// dpopNonceLife is how long a nonce is current; the one before stays good.
	dpopNonceLife = 5 * time.Minute
)

// dpopSigningAlgs are the proof algorithms the tenant accepts.
var dpopSigningAlgs = []string{"ES256"}

// dpopReplay remembers the proofs' jti values inside their window.
type dpopReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// fresh reports whether jti is unseen, and remembers it.
func (d *dpopReplay) fresh(jti string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[string]time.Time{}
	}
	for k, at := range d.seen {
		if now.Sub(at) > 2*dpopProofWindow {
			delete(d.seen, k)
		}
	}
	if _, ok := d.seen[jti]; ok {
		return false
	}
	d.seen[jti] = now
	return true
}

// dpopNonces is the server's current DPoP nonce and the one before it.
type dpopNonces struct {
	mu        sync.Mutex
	cur, prev string
	at        time.Time
}

func (n *dpopNonces) rotate(now time.Time) {
	if n.cur != "" && now.Sub(n.at) <= dpopNonceLife {
		return
	}
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	// The one before stays good only for a nonce life after it was replaced:
	// after an idle spell both are stale.
	n.prev = n.cur
	if now.Sub(n.at) > 2*dpopNonceLife {
		n.prev = ""
	}
	n.cur, n.at = base64.RawURLEncoding.EncodeToString(b), now
}

// current is the nonce a client should put in its next proof.
func (n *dpopNonces) current(now time.Time) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rotate(now)
	return n.cur
}

// valid reports whether nonce is the current one or the one before.
func (n *dpopNonces) valid(nonce string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rotate(now)
	return nonce != "" && (nonce == n.cur || nonce == n.prev)
}

// newDPoPValidator is the proof validator. Only its DPoP proof check is
// used, which reads none of the token options it requires.
func newDPoPValidator(key any) (*validator.Validator, error) {
	return validator.New(
		validator.WithKeyFunc(func(context.Context) (any, error) { return key, nil }),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuer("https://dpop.invalid/"),
		validator.WithAudience("https://dpop.invalid"),
	)
}

// proofOfPossession is the sender constraining of the API audience names.
func (s *Server) proofOfPossession(audience string) *config.ProofOfPossession {
	if audience == s.cfg.Audience {
		return s.cfg.ProofOfPossession
	}
	for _, a := range s.cfg.APIs {
		if a.Identifier == audience {
			return a.ProofOfPossession
		}
	}
	return nil
}

// publicClient is a client that holds no secret: a SPA or a native app.
func publicClient(c *config.Client) bool {
	return c != nil && (c.AppType == "spa" || c.AppType == "native")
}

// dpopGrant is what a token request's proof grants.
type dpopGrant struct {
	// jkt is the proof key's thumbprint; "" when the request had no proof.
	jkt string
	// bindAccess is true when the API takes DPoP: the access token is bound.
	bindAccess bool
}

// tokenType binds accessClaims to the proof's key when the API takes DPoP,
// and names the response's token type.
func (g dpopGrant) tokenType(accessClaims jwt.MapClaims) string {
	if g.jkt == "" || !g.bindAccess {
		return "Bearer"
	}
	accessClaims["cnf"] = map[string]any{"jkt": g.jkt}
	return "DPoP"
}

// errDPoPProof is a proof refused with invalid_dpop_proof.
type errDPoPProof string

func (e errDPoPProof) Error() string { return string(e) }

// checkProof validates proof for method and htu, made by a key with no
// private parts, fresh and unseen. ath, when not empty, is the access token
// the proof must name.
func (s *Server) checkProof(ctx context.Context, proof, method, htu, ath string) (*validator.DPoPProofClaims, error) {
	if err := publicJWKOnly(proof); err != nil {
		return nil, err
	}
	claims, err := s.dpop.ValidateDPoPProof(ctx, proof)
	if err != nil {
		return nil, errDPoPProof(err.Error())
	}
	now := time.Now()
	iat := time.Unix(claims.GetIAT(), 0)
	switch {
	case claims.GetHTM() != method:
		return nil, errDPoPProof("htm does not match the request")
	case !sameEndpoint(claims.GetHTU(), htu):
		return nil, errDPoPProof("htu does not match the request")
	case iat.Before(now.Add(-dpopProofWindow)) || iat.After(now.Add(dpopProofWindow)):
		return nil, errDPoPProof("iat is outside the acceptable window")
	case ath != "" && claims.GetATH() != ath:
		return nil, errDPoPProof("ath does not match the access token")
	}
	return claims, nil
}

// publicJWKOnly refuses a proof whose jwk header carries private key parts,
// or that is signed with an algorithm the tenant does not advertise.
func publicJWKOnly(proof string) error {
	head, _, ok := strings.Cut(proof, ".")
	if !ok {
		return errDPoPProof("malformed proof")
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return errDPoPProof("malformed proof header")
	}
	var h struct {
		Alg string         `json:"alg"`
		JWK map[string]any `json:"jwk"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return errDPoPProof("malformed proof header")
	}
	if !slices.Contains(dpopSigningAlgs, h.Alg) {
		return errDPoPProof("the proof's alg is not one the tenant accepts")
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, ok := h.JWK[private]; ok {
			return errDPoPProof("the proof's jwk carries a private key")
		}
	}
	return nil
}

// tokenDPoP checks a token request's DPoP proof for client and audience;
// bound is the key thumbprint the grant is bound to already (a refresh
// token's, or the authorize request's dpop_jkt), if any. On refusal it writes
// the error and returns false.
func (s *Server) tokenDPoP(w http.ResponseWriter, r *http.Request, client *config.Client, audience, bound string) (dpopGrant, bool) {
	refuse := func(code, description string) (dpopGrant, bool) {
		writeOAuthError(w, http.StatusBadRequest, code, description)
		return dpopGrant{}, false
	}
	pop := s.proofOfPossession(audience)
	takes := pop != nil && strings.EqualFold(pop.Mechanism, config.ProofOfPossessionDPoP)
	required := takes && pop.Required && (pop.RequiredFor != config.RequiredForPublicClients || publicClient(client))

	proofs := r.Header.Values(dpopHeader)
	switch {
	case len(proofs) > 1:
		return refuse("invalid_dpop_proof", "more than one DPoP proof")
	case len(proofs) == 0 || proofs[0] == "":
		if bound != "" {
			return refuse("invalid_dpop_proof", "the grant is bound to a DPoP key; send a proof made with it")
		}
		if required {
			return refuse("invalid_request", "this API requires a DPoP proof")
		}
		return dpopGrant{}, true
	}
	claims, err := s.checkProof(r.Context(), proofs[0], http.MethodPost, s.tokenEndpoint(), "")
	if err != nil {
		return refuse("invalid_dpop_proof", err.Error())
	}
	now := time.Now()
	if publicClient(client) {
		if !s.dpopNonces.valid(claims.Nonce, now) {
			w.Header().Set(dpopNonceHeader, s.dpopNonces.current(now))
			return refuse("use_dpop_nonce", "Authorization server requires nonce in DPoP proof")
		}
		w.Header().Set(dpopNonceHeader, s.dpopNonces.current(now))
	}
	if !s.dpopSeen.fresh(claims.GetJTI(), now) {
		return refuse("invalid_dpop_proof", "the proof's jti was already used")
	}
	jkt := claims.GetPublicKeyThumbprint()
	if bound != "" && jkt != bound {
		return refuse("invalid_dpop_proof", "the proof's key is not the one the grant is bound to")
	}
	return dpopGrant{jkt: jkt, bindAccess: takes}, true
}

// bindRefreshKey binds a refresh token to jkt if it is not bound yet, and
// reports whether it is bound to jkt (concurrent refreshes with different
// keys: one wins). An empty jkt binds nothing.
func (s *Server) bindRefreshKey(state *refreshTokenState, jkt string) bool {
	if jkt == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.DPoPJKT == "" {
		state.DPoPJKT = jkt
	}
	return state.DPoPJKT == jkt
}

// refreshKey is the key thumbprint a refresh token is bound to.
func (s *Server) refreshKey(state *refreshTokenState) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return state.DPoPJKT
}

// resourceDPoP checks a request to one of the tenant's own resources
// (/userinfo) whose access token is bound to tokenJKT: it needs the DPoP
// scheme and a proof from that key for this request and token.
func (s *Server) resourceDPoP(r *http.Request, token, tokenJKT, htu string) error {
	proofs := r.Header.Values(dpopHeader)
	if len(proofs) != 1 {
		return errors.New("one DPoP proof is required")
	}
	sum := sha256.Sum256([]byte(token))
	claims, err := s.checkProof(r.Context(), proofs[0], r.Method, htu, base64.RawURLEncoding.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	// Auth0 does not check jti reuse at /userinfo, so neither does the mock.
	if claims.GetPublicKeyThumbprint() != tokenJKT {
		return errors.New("the proof's key is not the token's")
	}
	return nil
}

// tokenJKT is an access token's cnf.jkt, or "".
func tokenJKT(claims jwt.MapClaims) string {
	cnf, _ := claims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

// dpopEnabled reports whether any of the tenant's APIs takes DPoP.
func (s *Server) dpopEnabled() bool {
	takes := func(p *config.ProofOfPossession) bool {
		return p != nil && strings.EqualFold(p.Mechanism, config.ProofOfPossessionDPoP)
	}
	if takes(s.cfg.ProofOfPossession) {
		return true
	}
	for _, a := range s.cfg.APIs {
		if takes(a.ProofOfPossession) {
			return true
		}
	}
	return false
}

func (s *Server) tokenEndpoint() string {
	return strings.TrimSuffix(s.cfg.Issuer, "/") + "/oauth/token"
}

// sameEndpoint compares two URLs by scheme, host and path, as RFC 9449 4.3
// compares htu: without query and fragment.
func sameEndpoint(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host) && ua.Path == ub.Path
}
