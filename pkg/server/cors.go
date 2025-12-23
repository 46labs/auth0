package server

import (
	"net/http"
	"strings"
)

func (s *Server) setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	for _, allowed := range s.cfg.CORSOrigins {
		if allowed == "*" || allowed == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if origin == "" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
			return
		}
		if strings.HasPrefix(allowed, "*.") && strings.HasSuffix(origin, allowed[1:]) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			return
		}
	}
}
