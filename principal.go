package oidcauth

import (
	"context"
	"time"
)

type contextKey uint8

const (
	principalContextKey contextKey = iota
	sessionContextKey
)

// Principal is a verified provider-neutral OIDC identity.
type Principal struct {
	Subject       string
	Issuer        string
	Audience      []string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	ExpiresAt     time.Time
	RawClaims     map[string]any
}

// Session contains a verified principal and its bounded browser-session expiry.
type Session struct {
	Principal Principal
	ExpiresAt time.Time
	idToken   string
}

// IDToken returns the verified raw ID token associated with the session.
func (s Session) IDToken() string {
	return s.idToken
}

// PrincipalFromContext returns the authenticated principal stored in a context.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey).(Principal)
	return principal, ok
}

// SessionFromContext returns the authenticated session stored in a context.
func SessionFromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(Session)
	return session, ok
}

// ContextWithPrincipal stores a verified principal in a context.
// It is primarily useful when adapting an application's existing middleware.
func ContextWithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey, principal)
}

func withSession(ctx context.Context, session Session) context.Context {
	ctx = ContextWithPrincipal(ctx, session.Principal)
	return context.WithValue(ctx, sessionContextKey, session)
}
