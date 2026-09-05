package oidcauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeProvider struct {
	server       *httptest.Server
	key          *rsa.PrivateKey
	kid          string
	mu           sync.Mutex
	nonce        string
	codeVerifier string
	tokenCalls   int
	jwksStatus   int
	tokenStatus  int
	tokenBody    string
	idToken      string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	provider := &fakeProvider{key: key, kid: "test-key", jwksStatus: http.StatusOK}
	provider.server = httptest.NewServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *fakeProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeTestJSON(w, map[string]any{
			"issuer":                 p.server.URL,
			"authorization_endpoint": p.server.URL + "/authorize",
			"token_endpoint":         p.server.URL + "/token",
			"jwks_uri":               p.server.URL + "/jwks",
			"end_session_endpoint":   p.server.URL + "/logout",
		})
	case "/jwks":
		p.mu.Lock()
		status := p.jwksStatus
		p.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		writeTestJSON(w, map[string]any{"keys": []any{p.jwk()}})
	case "/token":
		p.serveToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *fakeProvider) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.tokenCalls++
	nonce := p.nonce
	expectedVerifier := p.codeVerifier
	tokenStatus := p.tokenStatus
	tokenBody := p.tokenBody
	idTokenOverride := p.idToken
	p.mu.Unlock()
	if tokenStatus != 0 && tokenStatus != http.StatusOK {
		w.WriteHeader(tokenStatus)
		_, _ = w.Write([]byte(tokenBody))
		return
	}
	if r.Form.Get("code_verifier") != expectedVerifier {
		http.Error(w, "invalid verifier", http.StatusBadRequest)
		return
	}
	now := time.Now()
	idToken, err := p.sign(map[string]any{
		"iss":            p.server.URL,
		"sub":            "user-123",
		"aud":            "client-123",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"nonce":          nonce,
		"email":          "person@example.com",
		"email_verified": true,
		"name":           "Test Person",
		"given_name":     "Test",
		"family_name":    "Person",
		"picture":        "https://images.example.com/person.png",
		"department":     "safety",
	})
	if err != nil {
		http.Error(w, "sign token", http.StatusInternalServerError)
		return
	}
	if idTokenOverride != "" {
		idToken = idTokenOverride
	}
	writeTestJSON(w, map[string]any{
		"access_token": "access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (p *fakeProvider) jwk() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": p.kid,
		"n":   base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.PublicKey.E)).Bytes()),
	}
}

func (p *fakeProvider) sign(claims map[string]any) (string, error) {
	p.mu.Lock()
	key := p.key
	kid := p.kid
	p.mu.Unlock()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func TestVerifyRefreshesRotatedJWKS(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator := newTestAuthenticator(t, provider)
	now := time.Now()
	claims := func(subject string) map[string]any {
		return map[string]any{
			"iss": provider.server.URL,
			"sub": subject,
			"aud": "client-123",
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
		}
	}

	first, err := provider.sign(claims("before-rotation"))
	if err != nil {
		t.Fatalf("sign first token: %v", err)
	}
	if _, err := authenticator.Verify(t.Context(), first); err != nil {
		t.Fatalf("verify first token: %v", err)
	}

	rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rotated key: %v", err)
	}
	provider.mu.Lock()
	provider.key = rotatedKey
	provider.kid = "rotated-key"
	provider.mu.Unlock()

	second, err := provider.sign(claims("after-rotation"))
	if err != nil {
		t.Fatalf("sign rotated token: %v", err)
	}
	session, err := authenticator.Verify(t.Context(), second)
	if err != nil {
		t.Fatalf("verify rotated token: %v", err)
	}
	if session.Principal.Subject != "after-rotation" {
		t.Fatalf("rotated token subject = %q", session.Principal.Subject)
	}
}

func TestLoginCallbackAndMiddleware(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator := newTestAuthenticator(t, provider)
	loginResponse := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodGet, "/login?redirect_url=%2Fwork&login_hint=person%40example.com", nil)
	authenticator.LoginHandler(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login status = %d, want %d: %s", loginResponse.Code, http.StatusFound, loginResponse.Body.String())
	}
	location, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorization location: %v", err)
	}
	query := location.Query()
	if query.Get("nonce") == "" || query.Get("state") == "" {
		t.Fatalf("authorization URL lacks state or nonce: %s", location)
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("authorization URL lacks PKCE parameters: %s", location)
	}
	if query.Get("login_hint") != "person@example.com" {
		t.Fatalf("login_hint = %q", query.Get("login_hint"))
	}
	cookies := loginResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "oidc_transaction" || !cookies[0].HttpOnly {
		t.Fatalf("unexpected transaction cookies: %#v", cookies)
	}
	value, err := decryptTransaction(authenticator.config.StateEncryptionKey, cookies[0].Value, time.Now())
	if err != nil {
		t.Fatalf("decrypt transaction: %v", err)
	}
	provider.mu.Lock()
	provider.nonce = query.Get("nonce")
	provider.codeVerifier = value.CodeVerifier
	provider.mu.Unlock()

	callbackResponse := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/callback?code=authorization-code&state="+url.QueryEscape(query.Get("state")), nil)
	callbackRequest.AddCookie(cookies[0])
	authenticator.CallbackHandler(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want %d: %s", callbackResponse.Code, http.StatusFound, callbackResponse.Body.String())
	}
	if callbackResponse.Header().Get("Location") != "http://127.0.0.1:8888/work" {
		t.Fatalf("callback location = %q", callbackResponse.Header().Get("Location"))
	}
	var sessionCookie *http.Cookie
	for _, cookie := range callbackResponse.Result().Cookies() {
		if cookie.Name == "jwt" && cookie.Value != "" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("callback did not set the session cookie")
	}

	protected := authenticator.RequireAuthentication(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			t.Error("principal missing from context")
			return
		}
		if principal.Subject != "user-123" || principal.Email != "person@example.com" || !principal.EmailVerified {
			t.Errorf("unexpected principal: %#v", principal)
		}
		if principal.RawClaims["department"] != "safety" {
			t.Errorf("raw claims were not preserved: %#v", principal.RawClaims)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	protectedResponse := httptest.NewRecorder()
	protectedRequest := httptest.NewRequest(http.MethodGet, "/protected", nil)
	protectedRequest.Header.Set("Authorization", "Bearer "+sessionCookie.Value)
	protected.ServeHTTP(protectedResponse, protectedRequest)
	if protectedResponse.Code != http.StatusNoContent {
		t.Fatalf("protected status = %d: %s", protectedResponse.Code, protectedResponse.Body.String())
	}

	cookieResponse := httptest.NewRecorder()
	cookieRequest := httptest.NewRequest(http.MethodGet, "/protected", nil)
	cookieRequest.AddCookie(sessionCookie)
	protected.ServeHTTP(cookieResponse, cookieRequest)
	if cookieResponse.Code != http.StatusNoContent {
		t.Fatalf("session-cookie status = %d: %s", cookieResponse.Code, cookieResponse.Body.String())
	}
}

func TestCallbackRejectsMismatchedStateBeforeTokenExchange(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator := newTestAuthenticator(t, provider)
	loginResponse := httptest.NewRecorder()
	authenticator.LoginHandler(loginResponse, httptest.NewRequest(http.MethodGet, "/login", nil))
	cookie := loginResponse.Result().Cookies()[0]
	callbackResponse := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/callback?code=code&state=wrong", nil)
	callbackRequest.AddCookie(cookie)
	authenticator.CallbackHandler(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusBadRequest {
		t.Fatalf("callback status = %d, want %d", callbackResponse.Code, http.StatusBadRequest)
	}
	provider.mu.Lock()
	tokenCalls := provider.tokenCalls
	provider.mu.Unlock()
	if tokenCalls != 0 {
		t.Fatalf("token endpoint calls = %d, want 0", tokenCalls)
	}
}

func TestLoginRejectsUnallowedRedirect(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator := newTestAuthenticator(t, provider)
	response := httptest.NewRecorder()
	authenticator.LoginHandler(response, httptest.NewRequest(http.MethodGet, "/login?redirect_url=https%3A%2F%2Fevil.example%2Fsteal", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestMiddlewareRejectsOpaqueBearerTokens(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator := newTestAuthenticator(t, provider)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer opaque-token")
	authenticator.RequireAuthentication(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was called")
	})).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(response.Body.String(), `"code":"unauthorized"`) {
		t.Fatalf("unexpected response body: %s", response.Body.String())
	}
}

func TestReadyChecksJWKS(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator := newTestAuthenticator(t, provider)
	if err := authenticator.Ready(t.Context()); err != nil {
		t.Fatalf("ready returned error: %v", err)
	}
	provider.mu.Lock()
	provider.jwksStatus = http.StatusServiceUnavailable
	provider.mu.Unlock()
	if err := authenticator.Ready(t.Context()); err == nil {
		t.Fatal("ready succeeded with an unavailable JWKS")
	}
}

func TestNewRejectsInsecureNonLoopbackCookie(t *testing.T) {
	provider := newFakeProvider(t)
	config := testConfig(provider)
	config.DefaultRedirectURL = "https://app.example.com/dashboard"
	config.RedirectURL = "https://api.example.com/callback"
	if _, err := New(config); err == nil || !strings.Contains(err.Error(), "non-secure cookies") {
		t.Fatalf("New() error = %v", err)
	}
}

func TestLogoutClearsSessionAndUsesDiscoveredEndpoint(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator := newTestAuthenticator(t, provider)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/logout?redirect_url=%2Fsigned-out", nil)
	request.AddCookie(&http.Cookie{Name: "jwt", Value: "raw.id.token"})
	authenticator.LogoutHandler(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse logout location: %v", err)
	}
	if location.Path != "/logout" || location.Query().Get("id_token_hint") != "raw.id.token" {
		t.Fatalf("unexpected logout location: %s", location)
	}
	if location.Query().Get("post_logout_redirect_uri") != "http://127.0.0.1:8888/signed-out" {
		t.Fatalf("unexpected logout redirect: %s", location)
	}
	if len(response.Result().Cookies()) == 0 || response.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("session cookie was not cleared: %#v", response.Result().Cookies())
	}
}

func TestCallbackDoesNotExposeTokenEndpointResponseToLogsOrErrorHandler(t *testing.T) {
	provider := newFakeProvider(t)
	const sensitiveBody = `{"error":"invalid_client","client_secret":"do-not-leak"}`
	provider.mu.Lock()
	provider.tokenStatus = http.StatusUnauthorized
	provider.tokenBody = sensitiveBody
	provider.mu.Unlock()

	var logs bytes.Buffer
	var handledErr error
	config := testConfig(provider)
	config.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	config.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, status int, _ string, err error) {
		handledErr = err
		w.WriteHeader(status)
	}
	authenticator, err := New(config)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	loginResponse := httptest.NewRecorder()
	authenticator.LoginHandler(loginResponse, httptest.NewRequest(http.MethodGet, "/login", nil))
	location, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse login redirect: %v", err)
	}
	cookie := loginResponse.Result().Cookies()[0]
	value, err := decryptTransaction(authenticator.config.StateEncryptionKey, cookie.Value, time.Now())
	if err != nil {
		t.Fatalf("decrypt transaction: %v", err)
	}
	provider.mu.Lock()
	provider.nonce = location.Query().Get("nonce")
	provider.codeVerifier = value.CodeVerifier
	provider.mu.Unlock()

	callbackResponse := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/callback?code=authorization-code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callbackRequest.AddCookie(cookie)
	authenticator.CallbackHandler(callbackResponse, callbackRequest)

	if !errors.Is(handledErr, ErrAuthenticationFailed) {
		t.Fatalf("ErrorHandler error = %v, want ErrAuthenticationFailed", handledErr)
	}
	if strings.Contains(logs.String(), sensitiveBody) || strings.Contains(logs.String(), "do-not-leak") {
		t.Fatalf("logs exposed token response: %s", logs.String())
	}
	if strings.Contains(handledErr.Error(), "do-not-leak") {
		t.Fatalf("ErrorHandler exposed token response: %v", handledErr)
	}
}

func TestLoginDoesNotExposeDiscoveryResponseToLogsOrErrorHandler(t *testing.T) {
	const sensitiveBody = `{"error":"server_error","debug":"discovery-secret"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(sensitiveBody))
	}))
	t.Cleanup(server.Close)
	provider := &fakeProvider{server: server}

	var logs bytes.Buffer
	var handledErr error
	config := testConfig(provider)
	config.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	config.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, status int, _ string, err error) {
		handledErr = err
		w.WriteHeader(status)
	}
	authenticator, err := New(config)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	response := httptest.NewRecorder()
	authenticator.LoginHandler(response, httptest.NewRequest(http.MethodGet, "/login", nil))

	if !errors.Is(handledErr, ErrProviderUnavailable) {
		t.Fatalf("ErrorHandler error = %v, want ErrProviderUnavailable", handledErr)
	}
	if strings.Contains(logs.String(), sensitiveBody) || strings.Contains(logs.String(), "discovery-secret") {
		t.Fatalf("logs exposed discovery response: %s", logs.String())
	}
	if strings.Contains(handledErr.Error(), "discovery-secret") {
		t.Fatalf("ErrorHandler exposed discovery response: %v", handledErr)
	}
}

func TestCallbackDoesNotExposeInvalidIDTokenToLogsOrErrorHandler(t *testing.T) {
	provider := newFakeProvider(t)
	const sensitiveToken = "header.verification-secret.signature"
	provider.mu.Lock()
	provider.idToken = sensitiveToken
	provider.mu.Unlock()

	var logs bytes.Buffer
	var handledErr error
	config := testConfig(provider)
	config.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	config.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, status int, _ string, err error) {
		handledErr = err
		w.WriteHeader(status)
	}
	authenticator, err := New(config)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	loginResponse := httptest.NewRecorder()
	authenticator.LoginHandler(loginResponse, httptest.NewRequest(http.MethodGet, "/login", nil))
	location, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse login redirect: %v", err)
	}
	cookie := loginResponse.Result().Cookies()[0]
	value, err := decryptTransaction(authenticator.config.StateEncryptionKey, cookie.Value, time.Now())
	if err != nil {
		t.Fatalf("decrypt transaction: %v", err)
	}
	provider.mu.Lock()
	provider.nonce = location.Query().Get("nonce")
	provider.codeVerifier = value.CodeVerifier
	provider.mu.Unlock()

	callbackResponse := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/callback?code=authorization-code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callbackRequest.AddCookie(cookie)
	authenticator.CallbackHandler(callbackResponse, callbackRequest)

	if !errors.Is(handledErr, ErrAuthenticationFailed) {
		t.Fatalf("ErrorHandler error = %v, want ErrAuthenticationFailed", handledErr)
	}
	if strings.Contains(logs.String(), "verification-secret") || strings.Contains(handledErr.Error(), "verification-secret") {
		t.Fatalf("invalid ID token escaped sanitization: logs=%q error=%v", logs.String(), handledErr)
	}
}

func TestLogoutDoesNotExposeBuilderErrorToLogs(t *testing.T) {
	provider := newFakeProvider(t)
	const sensitiveError = "logout builder leaked private-token"
	var logs bytes.Buffer
	config := testConfig(provider)
	config.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	config.LogoutURLBuilder = func(LogoutRequest) (string, error) {
		return "", errors.New(sensitiveError)
	}
	authenticator, err := New(config)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/logout", nil)
	request.AddCookie(&http.Cookie{Name: "jwt", Value: "raw.id.token"})
	authenticator.LogoutHandler(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	if strings.Contains(logs.String(), sensitiveError) || strings.Contains(logs.String(), "private-token") {
		t.Fatalf("logs exposed logout builder error: %s", logs.String())
	}
}

func TestVerifyPreservesEmailNotVerifiedSentinel(t *testing.T) {
	provider := newFakeProvider(t)
	config := testConfig(provider)
	config.RequireVerifiedEmail = true
	authenticator, err := New(config)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}
	now := time.Now()
	rawIDToken, err := provider.sign(map[string]any{
		"iss":            provider.server.URL,
		"sub":            "user-123",
		"aud":            "client-123",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"email":          "person@example.com",
		"email_verified": false,
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = authenticator.Verify(t.Context(), rawIDToken)
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("Verify error = %v, want ErrEmailNotVerified", err)
	}
}

func TestErrorHandlerPreservesRecoverableTransactionErrorText(t *testing.T) {
	provider := newFakeProvider(t)
	var handledErr error
	config := testConfig(provider)
	config.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, status int, _ string, err error) {
		handledErr = err
		w.WriteHeader(status)
	}
	authenticator, err := New(config)
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}

	response := httptest.NewRecorder()
	authenticator.CallbackHandler(response, httptest.NewRequest(http.MethodGet, "/callback?code=code&state=state", nil))

	if handledErr == nil || handledErr.Error() != "authentication transaction cookie is missing" {
		t.Fatalf("ErrorHandler error = %v", handledErr)
	}
}

func newTestAuthenticator(t *testing.T, provider *fakeProvider) *Authenticator {
	t.Helper()
	authenticator, err := New(testConfig(provider))
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}
	return authenticator
}

func testConfig(provider *fakeProvider) Config {
	return Config{
		IssuerURL:          provider.server.URL,
		ClientID:           "client-123",
		ClientSecret:       "client-secret",
		RedirectURL:        "http://127.0.0.1:7777/callback",
		Scopes:             []string{"profile", "email"},
		DefaultRedirectURL: "http://127.0.0.1:8888/dashboard",
		StateEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		TransactionTTL:     10 * time.Minute,
		SessionMaxAge:      8 * time.Hour,
		TransactionCookie:  CookieConfig{Secure: false, SameSite: http.SameSiteLaxMode},
		SessionCookie:      CookieConfig{Secure: false, SameSite: http.SameSiteLaxMode},
	}
}

func writeTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}
