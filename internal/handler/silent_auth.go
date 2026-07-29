package handler

import (
	"net/http"
	"strings"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func SilentAuthMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !silentAuthenticate(r, token) {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
					return
				}
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func silentAuthenticate(r *http.Request, token string) bool {
	if !constants.IsAgentUserAgent(r.Header.Get(constants.HeaderUserAgent)) {
		return false
	}

	if token == "" {
		return true
	}

	value, ok := strings.CutPrefix(r.Header.Get(constants.HeaderAuthorization), constants.BearerPrefix)
	return ok && value == token
}
