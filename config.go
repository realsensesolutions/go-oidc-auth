package oidcauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultTransactionCookieName = "oidc_transaction"
	defaultSessionCookieName     = "jwt"
)

// CookieConfig controls a browser cookie created by the authenticator.
type CookieConfig struct {
	Name     string
	Path     string
	Domain   string
	Secure   bool
	SameSite http.SameSite
}

// LogoutRequest contains the provider-neutral values used to build a logout URL.
type LogoutRequest struct {
	EndSessionURL         string
	IDTokenHint           string
	PostLogoutRedirectURL string
	ClientID              string
}

// LogoutURLBuilder builds a provider-specific logout URL.
type LogoutURLBuilder func(LogoutRequest) (string, error)

// ErrorHandler writes a sanitized HTTP error response.
type ErrorHandler func(http.ResponseWriter, *http.Request, int, string, error)

// Config contains all OIDC protocol and browser-session configuration.
type Config struct {
	IssuerURL              string
	ClientID               string
	ClientSecret           string
	RedirectURL            string
	Scopes                 []string
	DefaultRedirectURL     string
	AllowedRedirectOrigins []string
	StateEncryptionKey     []byte
	TransactionTTL         time.Duration
	SessionMaxAge          time.Duration
	TransactionCookie      CookieConfig
	SessionCookie          CookieConfig
	RequireVerifiedEmail   bool
	EndSessionURL          string
	LogoutURLBuilder       LogoutURLBuilder
	HTTPClient             *http.Client
	Logger                 *slog.Logger
	ErrorHandler           ErrorHandler
}

func normalizeConfig(config Config) (Config, error) {
	config.IssuerURL = strings.TrimSpace(config.IssuerURL)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.RedirectURL = strings.TrimSpace(config.RedirectURL)
	config.DefaultRedirectURL = strings.TrimSpace(config.DefaultRedirectURL)
	config.EndSessionURL = strings.TrimSpace(config.EndSessionURL)
	if config.IssuerURL == "" {
		return Config{}, errors.New("issuer URL is required")
	}
	if config.ClientID == "" {
		return Config{}, errors.New("client ID is required")
	}
	redirectURL, err := validateAbsoluteHTTPURL(config.RedirectURL, "redirect URL")
	if err != nil {
		return Config{}, err
	}
	defaultRedirectURL, err := validateAbsoluteHTTPURL(config.DefaultRedirectURL, "default redirect URL")
	if err != nil {
		return Config{}, err
	}
	issuerURL, err := validateAbsoluteHTTPURL(config.IssuerURL, "issuer URL")
	if err != nil {
		return Config{}, err
	}
	if len(config.StateEncryptionKey) != 32 {
		return Config{}, errors.New("state encryption key must contain exactly 32 bytes")
	}
	config.StateEncryptionKey = append([]byte(nil), config.StateEncryptionKey...)
	if config.TransactionTTL <= 0 {
		return Config{}, errors.New("transaction TTL must be greater than zero")
	}
	if config.SessionMaxAge <= 0 {
		return Config{}, errors.New("session max age must be greater than zero")
	}
	if config.EndSessionURL != "" {
		if _, err := validateAbsoluteHTTPURL(config.EndSessionURL, "end-session URL"); err != nil {
			return Config{}, err
		}
	}

	config.TransactionCookie = normalizeCookie(config.TransactionCookie, defaultTransactionCookieName)
	config.SessionCookie = normalizeCookie(config.SessionCookie, defaultSessionCookieName)
	if err := validateCookieSecurity(config.TransactionCookie, redirectURL, defaultRedirectURL); err != nil {
		return Config{}, fmt.Errorf("transaction cookie: %w", err)
	}
	if err := validateCookieSecurity(config.SessionCookie, redirectURL, defaultRedirectURL); err != nil {
		return Config{}, fmt.Errorf("session cookie: %w", err)
	}

	allowedOrigins := make([]string, 0, len(config.AllowedRedirectOrigins)+1)
	seen := make(map[string]struct{}, len(config.AllowedRedirectOrigins)+1)
	for _, rawOrigin := range append(config.AllowedRedirectOrigins, origin(defaultRedirectURL)) {
		parsedOrigin, err := parseOrigin(rawOrigin)
		if err != nil {
			return Config{}, fmt.Errorf("allowed redirect origin %q: %w", rawOrigin, err)
		}
		if _, ok := seen[parsedOrigin]; ok {
			continue
		}
		seen[parsedOrigin] = struct{}{}
		allowedOrigins = append(allowedOrigins, parsedOrigin)
	}
	config.AllowedRedirectOrigins = allowedOrigins
	config.Scopes = normalizeScopes(config.Scopes)
	if config.HTTPClient == nil {
		config.HTTPClient = http.DefaultClient
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}
	config.IssuerURL = issuerURL.String()
	return config, nil
}

func normalizeCookie(cookie CookieConfig, defaultName string) CookieConfig {
	if cookie.Name == "" {
		cookie.Name = defaultName
	}
	if cookie.Path == "" {
		cookie.Path = "/"
	}
	if cookie.SameSite == http.SameSiteDefaultMode {
		cookie.SameSite = http.SameSiteLaxMode
	}
	return cookie
}

func validateCookieSecurity(cookie CookieConfig, URLs ...*url.URL) error {
	if strings.TrimSpace(cookie.Name) == "" {
		return errors.New("name is required")
	}
	if strings.ContainsAny(cookie.Name, "\t\r\n ;,") {
		return errors.New("name contains invalid characters")
	}
	if cookie.Path == "" || cookie.Path[0] != '/' {
		return errors.New("path must start with a slash")
	}
	if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
		return errors.New("SameSite=None requires Secure")
	}
	if cookie.Secure {
		return nil
	}
	for _, parsedURL := range URLs {
		if !isLoopbackHost(parsedURL.Hostname()) {
			return errors.New("non-secure cookies are allowed only for loopback development URLs")
		}
	}
	return nil
}

func validateAbsoluteHTTPURL(rawURL, field string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%s is invalid: %w", field, err)
	}
	if !parsedURL.IsAbs() || parsedURL.Host == "" || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
		return nil, fmt.Errorf("%s must be an absolute HTTP(S) URL", field)
	}
	if parsedURL.User != nil {
		return nil, fmt.Errorf("%s must not contain user information", field)
	}
	return parsedURL, nil
}

func parseOrigin(rawOrigin string) (string, error) {
	parsedURL, err := validateAbsoluteHTTPURL(strings.TrimSpace(rawOrigin), "origin")
	if err != nil {
		return "", err
	}
	if parsedURL.Path != "" && parsedURL.Path != "/" || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return "", errors.New("origin must not contain a path, query, or fragment")
	}
	return origin(parsedURL), nil
}

func origin(parsedURL *url.URL) string {
	return strings.ToLower(parsedURL.Scheme) + "://" + strings.ToLower(parsedURL.Host)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func normalizeScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes)+1)
	seen := make(map[string]struct{}, len(scopes)+1)
	for _, scope := range append([]string{"openid"}, scopes...) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}
