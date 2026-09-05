package oidcauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type providerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type providerState struct {
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauth2Config  oauth2.Config
	endSessionURL string
	jwksURL       string
}

// Authenticator implements OIDC login, verification, logout, and sessions.
type Authenticator struct {
	config   Config
	clock    func() time.Time
	provider *providerState
	mu       sync.Mutex
}

// New validates configuration without contacting the identity provider.
func New(config Config) (*Authenticator, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, fmt.Errorf("validate OIDC configuration: %w", err)
	}
	return &Authenticator{config: normalized, clock: time.Now}, nil
}

// Verify validates an ID token and returns a provider-neutral session.
func (a *Authenticator) Verify(ctx context.Context, rawIDToken string) (Session, error) {
	if strings.TrimSpace(rawIDToken) == "" {
		return Session{}, errors.New("ID token is empty")
	}
	state, err := a.providerState(ctx)
	if err != nil {
		return Session{}, err
	}
	ctx = a.providerContext(ctx)
	idToken, err := state.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Session{}, ErrAuthenticationFailed
	}
	session, err := a.sessionFromToken(idToken, rawIDToken)
	if err != nil {
		return Session{}, sanitizeError(errorCodeAuthentication, err)
	}
	return session, nil
}

// Ready verifies OIDC discovery and that the provider's JWKS is reachable.
func (a *Authenticator) Ready(ctx context.Context) error {
	state, err := a.providerState(ctx)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, state.jwksURL, nil)
	if err != nil {
		return ErrProviderUnavailable
	}
	response, err := a.config.HTTPClient.Do(request)
	if err != nil {
		return ErrProviderUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ErrProviderUnavailable
	}
	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&document); err != nil {
		return ErrProviderUnavailable
	}
	if len(document.Keys) == 0 {
		return ErrProviderUnavailable
	}
	return nil
}

func (a *Authenticator) providerState(ctx context.Context) (*providerState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.provider, nil
	}
	provider, err := oidc.NewProvider(a.providerContext(ctx), a.config.IssuerURL)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	var metadata providerMetadata
	if err := provider.Claims(&metadata); err != nil {
		return nil, ErrProviderUnavailable
	}
	if metadata.JWKSURI == "" {
		return nil, ErrProviderUnavailable
	}
	endpoint := provider.Endpoint()
	state := &providerState{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: a.config.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:     a.config.ClientID,
			ClientSecret: a.config.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  a.config.RedirectURL,
			Scopes:       append([]string(nil), a.config.Scopes...),
		},
		endSessionURL: metadata.EndSessionEndpoint,
		jwksURL:       metadata.JWKSURI,
	}
	if a.config.EndSessionURL != "" {
		state.endSessionURL = a.config.EndSessionURL
	}
	a.provider = state
	return state, nil
}

func (a *Authenticator) sessionFromToken(idToken *oidc.IDToken, rawIDToken string) (Session, error) {
	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		return Session{}, fmt.Errorf("decode ID token claims: %w", err)
	}
	principal := Principal{
		Subject:       idToken.Subject,
		Issuer:        idToken.Issuer,
		Audience:      append([]string(nil), idToken.Audience...),
		Email:         stringClaim(rawClaims, "email"),
		EmailVerified: boolClaim(rawClaims, "email_verified"),
		Name:          stringClaim(rawClaims, "name"),
		GivenName:     stringClaim(rawClaims, "given_name"),
		FamilyName:    stringClaim(rawClaims, "family_name"),
		Picture:       stringClaim(rawClaims, "picture"),
		ExpiresAt:     idToken.Expiry,
		RawClaims:     cloneClaims(rawClaims),
	}
	if principal.Subject == "" || principal.Issuer == "" {
		return Session{}, errors.New("ID token is missing issuer or subject")
	}
	if a.config.RequireVerifiedEmail && (principal.Email == "" || !principal.EmailVerified) {
		return Session{}, ErrEmailNotVerified
	}
	expiresAt := idToken.Expiry
	maximumExpiry := a.clock().Add(a.config.SessionMaxAge)
	if expiresAt.After(maximumExpiry) {
		expiresAt = maximumExpiry
	}
	if !expiresAt.After(a.clock()) {
		return Session{}, errors.New("ID token has expired")
	}
	return Session{Principal: principal, ExpiresAt: expiresAt, idToken: rawIDToken}, nil
}

func (a *Authenticator) validateNonce(session Session, expected string) error {
	actual := stringClaim(session.Principal.RawClaims, "nonce")
	if actual == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return errors.New("ID token nonce does not match authentication transaction")
	}
	return nil
}

func (a *Authenticator) providerContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, a.config.HTTPClient)
}

func (a *Authenticator) resolveRedirect(rawRedirect string) (string, error) {
	defaultURL, err := url.Parse(a.config.DefaultRedirectURL)
	if err != nil {
		return "", fmt.Errorf("parse configured default redirect URL: %w", err)
	}
	if strings.TrimSpace(rawRedirect) == "" {
		return defaultURL.String(), nil
	}
	redirectURL, err := url.Parse(rawRedirect)
	if err != nil {
		return "", errors.New("redirect URL is invalid")
	}
	if redirectURL.User != nil || redirectURL.Fragment != "" {
		return "", errors.New("redirect URL contains unsupported components")
	}
	if !redirectURL.IsAbs() {
		if redirectURL.Host != "" || !strings.HasPrefix(redirectURL.Path, "/") {
			return "", errors.New("relative redirect URL must start with a slash")
		}
		redirectURL = defaultURL.ResolveReference(redirectURL)
	}
	redirectOrigin := origin(redirectURL)
	for _, allowedOrigin := range a.config.AllowedRedirectOrigins {
		if redirectOrigin == allowedOrigin {
			return redirectURL.String(), nil
		}
	}
	return "", errors.New("redirect URL origin is not allowed")
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func boolClaim(claims map[string]any, name string) bool {
	switch value := claims[name].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(value, "true")
	default:
		return false
	}
}

func cloneClaims(claims map[string]any) map[string]any {
	clone := make(map[string]any, len(claims))
	for key, value := range claims {
		clone[key] = value
	}
	return clone
}
