package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"strings"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/require"
	"github.com/golang-jwt/jwt/v5"
)

// registerNPMModules provides the parts of jsonwebtoken and jwks-rsa an Action
// uses to verify a token this tenant issued, backed by the mock's own key, for
// an Action that declares them, as Auth0 installs only declared dependencies.
func (s *Server) registerNPMModules(registry *require.Registry, deps []ActionDependency) {
	declared := func(name string) bool {
		return slices.ContainsFunc(deps, func(d ActionDependency) bool { return d.Name == name })
	}
	if declared("jsonwebtoken") {
		s.registerJSONWebToken(registry)
	}
	if declared("jwks-rsa") {
		registry.RegisterNativeModule("jwks-rsa", func(vm *goja.Runtime, module *goja.Object) {
			_ = module.Set("exports", s.jwksClient(vm))
		})
	}
}

func (s *Server) registerJSONWebToken(registry *require.Registry) {
	registry.RegisterNativeModule("jsonwebtoken", func(vm *goja.Runtime, module *goja.Object) {
		exports := module.Get("exports").(*goja.Object)
		_ = exports.Set("verify", s.jwtVerify(vm))
		_ = exports.Set("decode", func(token string) goja.Value {
			claims, err := unverifiedClaims(token)
			if err != nil {
				return goja.Null()
			}
			return vm.ToValue(map[string]any(claims))
		})
	})
}

// jwksURI is where this tenant publishes its key set.
func (s *Server) jwksURI() string {
	return strings.TrimSuffix(s.cfg.Issuer, "/") + "/.well-known/jwks.json"
}

// jwksClient is jwks-rsa's default export: jwksClient({jwksUri}) with
// getSigningKey(kid[, cb]). The key's getPublicKey() is the SPKI PEM.
func (s *Server) jwksClient(vm *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		uri := ""
		if o, ok := call.Argument(0).(*goja.Object); ok {
			if v := o.Get("jwksUri"); v != nil && !goja.IsUndefined(v) {
				uri = v.String()
			}
		}
		client := vm.NewObject()
		_ = client.Set("getSigningKey", func(c goja.FunctionCall) goja.Value {
			key, err := s.signingKey(vm, uri, c.Argument(0).String())
			errVal := goja.Null()
			if err != nil {
				errVal = vm.NewGoError(err)
			}
			if cb, ok := goja.AssertFunction(c.Argument(1)); ok {
				_, _ = cb(goja.Undefined(), errVal, key)
				return goja.Undefined()
			}
			p, resolve, reject := vm.NewPromise()
			if err != nil {
				_ = reject(errVal)
			} else {
				_ = resolve(key)
			}
			return vm.ToValue(p)
		})
		return client
	}
}

func (s *Server) signingKey(vm *goja.Runtime, uri, kid string) (goja.Value, error) {
	if uri != s.jwksURI() {
		return goja.Undefined(), errors.New("jwks-rsa in the auth0 mock serves only this tenant's key set, " + s.jwksURI() + ", not " + uri)
	}
	if kid != "key-1" {
		return goja.Undefined(), errors.New("Unable to find a signing key that matches '" + kid + "'")
	}
	der, err := x509.MarshalPKIXPublicKey(&s.privateKey.PublicKey)
	if err != nil {
		return goja.Undefined(), err
	}
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	key := vm.NewObject()
	_ = key.Set("kid", kid)
	_ = key.Set("alg", "RS256")
	_ = key.Set("publicKey", pub)
	_ = key.Set("rsaPublicKey", pub)
	_ = key.Set("getPublicKey", func() string { return pub })
	return key, nil
}

// jwtVerify is jsonwebtoken.verify(token, keyOrGetter[, options][, callback]),
// with RS256 PEM keys and the algorithms, issuer and audience options. Errors
// carry jsonwebtoken's names and messages.
func (s *Server) jwtVerify(vm *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		token := call.Argument(0).String()
		var opts *goja.Object
		var cb goja.Callable
		for _, a := range call.Arguments[min(2, len(call.Arguments)):] {
			if f, ok := goja.AssertFunction(a); ok {
				cb = f
			} else if o, ok := a.(*goja.Object); ok {
				opts = o
			}
		}
		finish := func(errVal, decoded goja.Value) goja.Value {
			if cb != nil {
				_, _ = cb(goja.Undefined(), errVal, decoded)
				return goja.Undefined()
			}
			if !goja.IsNull(errVal) {
				panic(errVal)
			}
			return decoded
		}
		verify := func(key string) goja.Value {
			claims, name, msg := verifyToken(token, key, opts)
			if name != "" {
				return finish(jwtError(vm, name, msg), goja.Undefined())
			}
			return finish(goja.Null(), vm.ToValue(map[string]any(claims)))
		}

		getter, isGetter := goja.AssertFunction(call.Argument(1))
		if !isGetter {
			return verify(call.Argument(1).String())
		}
		if cb == nil {
			panic(jwtError(vm, "JsonWebTokenError", "verify must be called asynchronous if secret or public key is provided as a callback"))
		}
		header, err := tokenHeader(token)
		if err != nil {
			return finish(jwtError(vm, "JsonWebTokenError", "jwt malformed"), goja.Undefined())
		}
		_, _ = getter(goja.Undefined(), vm.ToValue(header), vm.ToValue(func(c goja.FunctionCall) goja.Value {
			if e := c.Argument(0); !goja.IsUndefined(e) && !goja.IsNull(e) {
				finish(jwtError(vm, "JsonWebTokenError", "error in secret or public key callback: "+e.String()), goja.Undefined())
				return goja.Undefined()
			}
			verify(c.Argument(1).String())
			return goja.Undefined()
		}))
		return goja.Undefined()
	}
}

// verifyToken checks the signature, expiry, algorithm, issuer and audience.
// A failure returns jsonwebtoken's error name and message.
func verifyToken(token, keyPEM string, opts *goja.Object) (claims jwt.MapClaims, name, msg string) {
	algorithms := []string{"RS256"}
	if v := optStrings(opts, "algorithms"); len(v) > 0 {
		algorithms = v
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(keyPEM))
	if err != nil {
		return nil, "JsonWebTokenError", "secretOrPublicKey must be an asymmetric key when using RS256"
	}
	claims = jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods(algorithms))
	switch {
	case err == nil:
	case errors.Is(err, jwt.ErrTokenMalformed):
		return nil, "JsonWebTokenError", "jwt malformed"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid) && strings.Contains(err.Error(), "signing method"):
		return nil, "JsonWebTokenError", "invalid algorithm"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return nil, "JsonWebTokenError", "invalid signature"
	case errors.Is(err, jwt.ErrTokenExpired):
		return nil, "TokenExpiredError", "jwt expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return nil, "NotBeforeError", "jwt not active"
	default:
		return nil, "JsonWebTokenError", err.Error()
	}

	if want := optStrings(opts, "issuer"); len(want) > 0 {
		if iss, _ := claims["iss"].(string); !slices.Contains(want, iss) {
			return nil, "JsonWebTokenError", "jwt issuer invalid. expected: " + strings.Join(want, ",")
		}
	}
	if want := optStrings(opts, "audience"); len(want) > 0 {
		aud, _ := claims.GetAudience()
		if !slices.ContainsFunc(aud, func(a string) bool { return slices.Contains(want, a) }) {
			return nil, "JsonWebTokenError", "jwt audience invalid. expected: " + strings.Join(want, " or ")
		}
	}
	return claims, "", ""
}

// optStrings reads an option that is a string or an array of them.
func optStrings(opts *goja.Object, name string) []string {
	if opts == nil {
		return nil
	}
	v := opts.Get(name)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	switch x := v.Export().(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func jwtError(vm *goja.Runtime, name, msg string) goja.Value {
	e, _ := vm.New(vm.Get("Error"), vm.ToValue(msg))
	_ = e.Set("name", name)
	return e
}

func tokenHeader(token string) (map[string]any, error) {
	part, _, ok := strings.Cut(token, ".")
	if !ok {
		return nil, jwt.ErrTokenMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	var h map[string]any
	return h, json.Unmarshal(raw, &h)
}

func unverifiedClaims(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	return claims, err
}
