package oidcauth

import (
	"errors"
	"net/http"
	"strings"
)

// RequireAuthentication accepts a JWT Bearer token or the configured session cookie.
func (a *Authenticator) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawToken, err := a.authenticationToken(r)
		if err != nil {
			a.writeError(w, r, http.StatusUnauthorized, errorCodeUnauthorized, err)
			return
		}
		session, err := a.Verify(r.Context(), rawToken)
		if err != nil {
			a.writeError(w, r, http.StatusUnauthorized, errorCodeUnauthorized, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), session)))
	})
}

func (a *Authenticator) authenticationToken(r *http.Request) (string, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization != "" {
		parts := strings.Fields(authorization)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			return "", errors.New("Authorization header must contain a Bearer token")
		}
		if !isJWT(parts[1]) {
			return "", errors.New("opaque Bearer tokens are not supported")
		}
		return parts[1], nil
	}
	cookie, err := r.Cookie(a.config.SessionCookie.Name)
	if err != nil || cookie.Value == "" {
		return "", errors.New("authentication token is missing")
	}
	return cookie.Value, nil
}

func isJWT(token string) bool {
	return strings.Count(token, ".") == 2
}
