package oidcauth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// LoginHandler starts an OIDC Authorization Code Flow with PKCE.
func (a *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	redirectURL, err := a.resolveRedirect(r.URL.Query().Get("redirect_url"))
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, errorCodeInvalidRequest, err)
		return
	}
	state, err := a.providerState(r.Context())
	if err != nil {
		a.writeError(w, r, http.StatusServiceUnavailable, errorCodeProviderUnavailable, err)
		return
	}
	now := a.clock()
	value, err := newTransaction(redirectURL, now, a.config.TransactionTTL)
	if err != nil {
		a.writeError(w, r, http.StatusInternalServerError, errorCodeAuthentication, err)
		return
	}
	encrypted, err := encryptTransaction(a.config.StateEncryptionKey, value)
	if err != nil {
		a.writeError(w, r, http.StatusInternalServerError, errorCodeAuthentication, err)
		return
	}
	http.SetCookie(w, transactionCookie(a.config.TransactionCookie, encrypted, value.ExpiresAt, int(time.Until(value.ExpiresAt).Seconds())))
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", value.Nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge(value.CodeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if loginHint := strings.TrimSpace(r.URL.Query().Get("login_hint")); loginHint != "" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", loginHint))
	}
	authURL := state.oauth2Config.AuthCodeURL(value.State, options...)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// CallbackHandler completes an OIDC Authorization Code Flow and creates a session.
func (a *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if providerError := strings.TrimSpace(r.URL.Query().Get("error")); providerError != "" {
		a.clearTransactionCookie(w)
		a.writeError(w, r, http.StatusBadRequest, errorCodeAuthentication, fmt.Errorf("provider returned %s", providerError))
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	receivedState := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || receivedState == "" {
		a.writeError(w, r, http.StatusBadRequest, errorCodeInvalidRequest, errors.New("code and state are required"))
		return
	}
	cookie, err := r.Cookie(a.config.TransactionCookie.Name)
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, errorCodeInvalidRequest, errors.New("authentication transaction cookie is missing"))
		return
	}
	value, err := decryptTransaction(a.config.StateEncryptionKey, cookie.Value, a.clock())
	a.clearTransactionCookie(w)
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, errorCodeInvalidRequest, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(value.State), []byte(receivedState)) != 1 {
		a.writeError(w, r, http.StatusBadRequest, errorCodeInvalidRequest, errors.New("OAuth state does not match transaction"))
		return
	}
	provider, err := a.providerState(r.Context())
	if err != nil {
		a.writeError(w, r, http.StatusServiceUnavailable, errorCodeProviderUnavailable, err)
		return
	}
	ctx := a.providerContext(r.Context())
	token, err := provider.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", value.CodeVerifier))
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, errorCodeAuthentication, fmt.Errorf("exchange authorization code: %w", err))
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		a.writeError(w, r, http.StatusBadRequest, errorCodeAuthentication, errors.New("token response does not contain an ID token"))
		return
	}
	session, err := a.Verify(ctx, rawIDToken)
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, errorCodeAuthentication, err)
		return
	}
	if err := a.validateNonce(session, value.Nonce); err != nil {
		a.writeError(w, r, http.StatusBadRequest, errorCodeAuthentication, err)
		return
	}
	a.setSessionCookie(w, session)
	http.Redirect(w, r, value.RedirectURL, http.StatusFound)
}

// LogoutHandler clears the local session and redirects through provider logout when available.
func (a *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	redirectURL, err := a.resolveRedirect(r.URL.Query().Get("redirect_url"))
	if err != nil {
		a.writeError(w, r, http.StatusBadRequest, errorCodeInvalidRequest, err)
		return
	}
	idTokenHint := ""
	if cookie, cookieErr := r.Cookie(a.config.SessionCookie.Name); cookieErr == nil {
		idTokenHint = cookie.Value
	}
	a.clearSessionCookie(w)
	provider, providerErr := a.providerState(r.Context())
	if providerErr != nil {
		a.config.Logger.WarnContext(r.Context(), "OIDC logout discovery failed; local session was cleared", "error", providerErr)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	logoutURL, err := a.logoutURL(provider.endSessionURL, idTokenHint, redirectURL)
	if err != nil {
		a.config.Logger.WarnContext(r.Context(), "OIDC logout URL could not be built; local session was cleared", "error", err)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	if logoutURL == "" {
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func (a *Authenticator) logoutURL(endSessionURL, idTokenHint, redirectURL string) (string, error) {
	request := LogoutRequest{
		EndSessionURL:         endSessionURL,
		IDTokenHint:           idTokenHint,
		PostLogoutRedirectURL: redirectURL,
		ClientID:              a.config.ClientID,
	}
	if a.config.LogoutURLBuilder != nil {
		return a.config.LogoutURLBuilder(request)
	}
	if endSessionURL == "" {
		return "", nil
	}
	parsedURL, err := url.Parse(endSessionURL)
	if err != nil || !parsedURL.IsAbs() || parsedURL.Host == "" {
		return "", errors.New("provider end-session URL is invalid")
	}
	query := parsedURL.Query()
	if idTokenHint != "" {
		query.Set("id_token_hint", idTokenHint)
	}
	query.Set("post_logout_redirect_uri", redirectURL)
	query.Set("client_id", a.config.ClientID)
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

func (a *Authenticator) setSessionCookie(w http.ResponseWriter, session Session) {
	maxAge := int(session.ExpiresAt.Sub(a.clock()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.config.SessionCookie.Name,
		Value:    session.IDToken(),
		Path:     a.config.SessionCookie.Path,
		Domain:   a.config.SessionCookie.Domain,
		Expires:  session.ExpiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.config.SessionCookie.Secure,
		SameSite: a.config.SessionCookie.SameSite,
	})
}

func (a *Authenticator) clearTransactionCookie(w http.ResponseWriter) {
	http.SetCookie(w, transactionCookie(a.config.TransactionCookie, "", time.Unix(1, 0), -1))
}

func (a *Authenticator) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.config.SessionCookie.Name,
		Path:     a.config.SessionCookie.Path,
		Domain:   a.config.SessionCookie.Domain,
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.config.SessionCookie.Secure,
		SameSite: a.config.SessionCookie.SameSite,
	})
}

func (a *Authenticator) writeError(w http.ResponseWriter, r *http.Request, status int, code string, err error) {
	a.config.Logger.WarnContext(r.Context(), "OIDC request failed", "code", code, "status", status, "error", err)
	a.config.ErrorHandler(w, r, status, code, err)
}
