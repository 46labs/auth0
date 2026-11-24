package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
)

// signingKey is the tenant's one RS256 key. Its kid is the key's RFC 7638
// thumbprint, so a different key always carries a different kid: a verifier
// holding a cached key set sees an unknown kid and refetches, instead of
// checking a new signature against the old key under a reused kid.
type signingKey struct {
	private *rsa.PrivateKey
	kid     string
}

// loadSigningKey reads a PEM RSA private key (PKCS#1 or PKCS#8) from path, or
// generates one when path is empty. A configured path that cannot be used
// fails startup rather than falling back to a key nobody else holds.
func loadSigningKey(path string) (*signingKey, error) {
	var key *rsa.PrivateKey
	if path == "" {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		key = k
	} else {
		k, err := readRSAPrivateKey(path)
		if err != nil {
			return nil, fmt.Errorf("signing key %s: %w", path, err)
		}
		key = k
	}
	thumb, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing key thumbprint: %w", err)
	}
	return &signingKey{private: key, kid: base64.RawURLEncoding.EncodeToString(thumb)}, nil
}

func readRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no RSA private key PEM block")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is %T, RS256 needs RSA", k)
			}
			return rk, nil
		}
	}
}

// jwks is the tenant key set as published at /.well-known/jwks.json.
func (s *Server) jwks() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.privateKey.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"}}}
}
