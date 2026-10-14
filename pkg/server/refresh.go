package server

import (
	"net/http"
	"time"

	"github.com/46labs/auth0/pkg/config"
)

// unknownRefreshTokenError is Auth0's answer, with HTTP 403, to a refresh token it
// does not know, including one a rotation retired or a breach revoked.
const unknownRefreshTokenError = `{"error":"invalid_grant","error_description":"Unknown or invalid refresh token."}`

const wrongClientRefreshTokenError = `{"error":"invalid_grant","error_description":"the refresh token was issued to a different client"}`

// redeemRefreshToken claims a refresh token for a refresh by clientID and, when
// the client rotates refresh tokens, replaces it, under one lock so concurrent
// refreshes see one consistent family. It returns the token's state and the new
// refresh token ("" without rotation), or an error body and status.
//
// A token a rotation retired is reuse. Within the client's leeway (Auth0's reuse
// interval) the most recently retired token of its family is exchanged as usual;
// any other reuse revokes the whole family, as Auth0's breach detection does.
func (s *Server) redeemRefreshToken(token, clientID string, client *config.Client, now time.Time) (*refreshTokenState, string, string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, live := s.refreshTokens[token]
	if !live {
		retired, ok := s.retiredRefreshTokens[token]
		if !ok {
			return nil, "", unknownRefreshTokenError, http.StatusForbidden
		}
		if !s.reusableWithinLeeway(token, retired, client, now) {
			s.revokeRefreshTokenFamily(retired.State.Family)
			return nil, "", unknownRefreshTokenError, http.StatusForbidden
		}
		state = retired.State
	}
	// The token belongs to the client the login was authorized for;
	// otherwise the audience and action client context could be swapped.
	if state.ClientID != "" && clientID != state.ClientID {
		return nil, "", wrongClientRefreshTokenError, http.StatusBadRequest
	}
	if !client.RotatesRefreshTokens() {
		return state, "", "", 0
	}

	rotated := "rt_" + s.generateID()
	if live {
		delete(s.refreshTokens, token)
		s.retiredRefreshTokens[token] = &retiredRefreshToken{State: state, RetiredAt: now}
	}
	s.refreshTokens[rotated] = state
	return state, rotated, "", 0
}

// reusableWithinLeeway reports whether a retired token is the latest one its
// family retired and was retired no longer ago than the client's leeway. Caller
// holds s.mu.
func (s *Server) reusableWithinLeeway(token string, retired *retiredRefreshToken, client *config.Client, now time.Time) bool {
	leeway := client.RefreshTokenLeeway()
	if leeway <= 0 || now.Sub(retired.RetiredAt) > leeway {
		return false
	}
	for other, candidate := range s.retiredRefreshTokens {
		if other != token && candidate.State.Family == retired.State.Family && candidate.RetiredAt.After(retired.RetiredAt) {
			return false
		}
	}
	return true
}

// revokeRefreshTokenFamily forgets every live and retired token of a family.
// Caller holds s.mu.
func (s *Server) revokeRefreshTokenFamily(family string) {
	for token, state := range s.refreshTokens {
		if state.Family == family {
			delete(s.refreshTokens, token)
		}
	}
	for token, retired := range s.retiredRefreshTokens {
		if retired.State.Family == family {
			delete(s.retiredRefreshTokens, token)
		}
	}
}
