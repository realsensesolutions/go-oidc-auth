package oidcauth

import (
	"encoding/json"
	"errors"
	"net/http"
)

var (
	// ErrEmailNotVerified indicates that a verified email was required but absent.
	ErrEmailNotVerified = errors.New("ID token does not contain a verified email")
	// ErrInvalidRequest indicates that authentication request input was invalid.
	ErrInvalidRequest = errors.New("invalid authentication request")
	// ErrAuthenticationFailed indicates that authentication could not be completed.
	ErrAuthenticationFailed = errors.New("authentication failed")
	// ErrUnauthorized indicates that a valid authentication session was not provided.
	ErrUnauthorized = errors.New("authentication session is unauthorized")
	// ErrProviderUnavailable indicates that the identity provider could not be reached or used.
	ErrProviderUnavailable = errors.New("identity provider unavailable")
)

var (
	errTransactionCookieMissing    = errors.New("authentication transaction cookie is missing")
	errTransactionCookieMalformed  = errors.New("transaction cookie is malformed")
	errTransactionCookieInvalid    = errors.New("transaction cookie is invalid")
	errTransactionCookieIncomplete = errors.New("transaction cookie is incomplete")
	errTransactionCookieExpired    = errors.New("transaction cookie has expired")
)

const (
	errorCodeInvalidRequest      = "invalid_request"
	errorCodeAuthentication      = "authentication_failed"
	errorCodeUnauthorized        = "unauthorized"
	errorCodeProviderUnavailable = "provider_unavailable"
	messageInvalidRequest        = "The authentication request is invalid."
	messageAuthentication        = "Authentication failed."
	messageUnauthorized          = "A valid authentication session is required."
	messageProviderUnavailable   = "The identity provider is temporarily unavailable."
)

type errorResponse struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, status int, code string, _ error) {
	message := messageAuthentication
	switch code {
	case errorCodeInvalidRequest:
		message = messageInvalidRequest
	case errorCodeUnauthorized:
		message = messageUnauthorized
	case errorCodeProviderUnavailable:
		message = messageProviderUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: errorBody{Code: code, Message: message}})
}

func sanitizeError(code string, err error) error {
	if errors.Is(err, ErrEmailNotVerified) {
		return ErrEmailNotVerified
	}
	switch {
	case errors.Is(err, errTransactionCookieMissing):
		return errTransactionCookieMissing
	case errors.Is(err, errTransactionCookieMalformed):
		return errTransactionCookieMalformed
	case errors.Is(err, errTransactionCookieInvalid):
		return errTransactionCookieInvalid
	case errors.Is(err, errTransactionCookieIncomplete):
		return errTransactionCookieIncomplete
	case errors.Is(err, errTransactionCookieExpired):
		return errTransactionCookieExpired
	}
	switch code {
	case errorCodeInvalidRequest:
		return ErrInvalidRequest
	case errorCodeUnauthorized:
		return ErrUnauthorized
	case errorCodeProviderUnavailable:
		return ErrProviderUnavailable
	default:
		return ErrAuthenticationFailed
	}
}
