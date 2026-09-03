package oidcauth

import (
	"encoding/json"
	"errors"
	"net/http"
)

// ErrEmailNotVerified indicates that a verified email was required but absent.
var ErrEmailNotVerified = errors.New("ID token does not contain a verified email")

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
