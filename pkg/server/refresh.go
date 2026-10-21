package server

import (
	"net/http"
	"time"

	"github.com/46labs/auth0/pkg/config"
)

// unknownRefreshTokenError is Auth0's answer, with HTTP 403, to a refresh token it
// does not know, including one a rotation retired or a breach revoked.
const unknownRefreshTokenError = "Unknown or invalid refresh token."

const wrongClientRefreshTokenError = "the refresh token was issued to a different client"

// claimRefreshToken checks a refresh by clientID without changing a live
// token; reuse of a retired one outside its leeway revokes the family. The
// caller runs release when the refresh ends.
func (s *Server) claimRefreshToken(token, clientID string, now time.Time) (state *refreshTokenState, release func(), errDescription string, status int) {
	release = func() {}
	s.mu.Lock()
	defer s.mu.Unlock()

	state, live := s.refreshTokens[token]
	retired, wasRetired := s.retiredRefreshTokens[token]
	if !live && !wasRetired {
		return nil, release, unknownRefreshTokenError, http.StatusForbidden
	}
	if !live {
		state = retired.State
	}
	// Checked first: another client presenting the token changes nothing.
	if state.ClientID != "" && clientID != state.ClientID {
		return nil, release, wrongClientRefreshTokenError, http.StatusBadRequest
	}
	client := s.clients[state.ClientID]
	if !live && !s.reusableWithinLeeway(token, retired, client, now) {
		s.revokeRefreshTokenFamily(state.Family)
		return nil, release, unknownRefreshTokenError, http.StatusForbidden
	}
	// Without a leeway a concurrent use is reuse: refused before its Action
	// runs, and a breach once the refresh in flight rotates.
	if live && client.RotatesRefreshTokens() && client.RefreshTokenLeeway() <= 0 {
		if _, inFlight := s.refreshInFlight[token]; inFlight {
			s.refreshInFlight[token] = true
			return nil, release, unknownRefreshTokenError, http.StatusForbidden
		}
		s.refreshInFlight[token] = false
		release = func() {
			s.mu.Lock()
			delete(s.refreshInFlight, token)
			s.mu.Unlock()
		}
	}
	return state, release, "", 0
}

// rotateRefreshToken replaces token once its claimed refresh has succeeded, for
// a client that rotates; it fails if the family was revoked or reused meanwhile.
func (s *Server) rotateRefreshToken(token string, state *refreshTokenState) (string, string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	client := s.clients[state.ClientID]
	if !client.RotatesRefreshTokens() {
		return "", "", 0
	}
	if s.refreshInFlight[token] {
		s.revokeRefreshTokenFamily(state.Family)
		return "", unknownRefreshTokenError, http.StatusForbidden
	}
	if _, live := s.refreshTokens[token]; live {
		delete(s.refreshTokens, token)
		s.retiredRefreshTokens[token] = &retiredRefreshToken{State: state, RetiredAt: time.Now()}
	} else if _, ok := s.retiredRefreshTokens[token]; !ok {
		s.revokeRefreshTokenFamily(state.Family)
		return "", unknownRefreshTokenError, http.StatusForbidden
	}
	rotated := s.newRefreshToken()
	s.refreshTokens[rotated] = state
	return rotated, "", 0
}

// reusableWithinLeeway reports whether a retired token is its family's latest
// and within the client's leeway. Caller holds s.mu.
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

// newRefreshToken mints a refresh token id.
func (s *Server) newRefreshToken() string {
	return "rt_" + s.generateID()
}
