# go-oidc-auth

Provider-neutral OpenID Connect authentication for Go `net/http`
applications. The module has no AWS, Cognito, Authentik, Chi, database, or
application dependencies.

## Features

- OIDC discovery and rotating JWKS verification
- Authorization Code Flow with PKCE, state, and nonce
- encrypted, expiring, stateless transaction cookies
- verified ID-token sessions in an `HttpOnly` cookie
- JWT Bearer and session-cookie middleware
- provider-neutral `Principal` and `Session` context values
- safe return-URL allowlisting
- discovery/JWKS readiness checks
- configurable structured logging and JSON errors

Opaque Bearer tokens are deliberately rejected. Provider administration,
application roles, profile responses, and profile routes belong outside this
module.

## Example

```go
authenticator, err := oidcauth.New(oidcauth.Config{
	IssuerURL:          "https://identity.example.com/application/o/cloudloto/",
	ClientID:           os.Getenv("OIDC_CLIENT_ID"),
	ClientSecret:       os.Getenv("OIDC_CLIENT_SECRET"),
	RedirectURL:        "https://api.example.com/oauth2/idpresponse",
	Scopes:             []string{"openid", "email", "profile"},
	DefaultRedirectURL: "https://app.example.com/dashboard",
	StateEncryptionKey: stateEncryptionKey, // exactly 32 bytes; no fallback exists
	TransactionTTL:     5 * time.Minute,
	SessionMaxAge:      8 * time.Hour,
	TransactionCookie: oidcauth.CookieConfig{
		Name: "oidc_transaction", Path: "/", Secure: true,
		SameSite: http.SameSiteLaxMode,
	},
	SessionCookie: oidcauth.CookieConfig{
		Name: "jwt", Path: "/", Secure: true,
		SameSite: http.SameSiteNoneMode,
	},
})
if err != nil {
	return err
}

mux.HandleFunc("/api/auth/login", authenticator.LoginHandler)
mux.HandleFunc("/oauth2/idpresponse", authenticator.CallbackHandler)
mux.HandleFunc("/api/auth/logout", authenticator.LogoutHandler)
mux.Handle("/api/profile", authenticator.RequireAuthentication(profileHandler))
```

The application can read the verified identity with:

```go
principal, ok := oidcauth.PrincipalFromContext(r.Context())
```

Stable identity is the pair `(principal.Issuer, principal.Subject)`, never an
email address alone.

## Security contract

Configuration is explicit: the package does not read environment variables or
use globals. A 32-byte OAuth state encryption key is required. Redirects must
be relative to the configured application origin or match an explicitly
allowed origin. Non-secure cookies are accepted only when all configured URLs
use loopback hosts.

`Verify` checks issuer, audience, signature, and expiry through the discovered
provider. The callback also verifies the transaction state, PKCE verifier, and
ID-token nonce before creating a session.

Provider response bodies and low-level discovery, token-exchange, verification,
and logout errors are never written to the configured logger or passed to an
`ErrorHandler`. Consumers receive stable errors that can be matched with
`errors.Is`: `ErrInvalidRequest`, `ErrAuthenticationFailed`, `ErrUnauthorized`,
`ErrProviderUnavailable`, and `ErrEmailNotVerified`.
