package oidcauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type transaction struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	RedirectURL  string    `json:"redirect_url"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func newTransaction(redirectURL string, now time.Time, ttl time.Duration) (transaction, error) {
	state, err := randomToken(32)
	if err != nil {
		return transaction{}, fmt.Errorf("generate state: %w", err)
	}
	nonce, err := randomToken(32)
	if err != nil {
		return transaction{}, fmt.Errorf("generate nonce: %w", err)
	}
	verifier, err := randomToken(32)
	if err != nil {
		return transaction{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	return transaction{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		RedirectURL:  redirectURL,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}, nil
}

func encryptTransaction(key []byte, value transaction) (string, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal transaction: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate encryption nonce: %w", err)
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func decryptTransaction(key []byte, encoded string, now time.Time) (transaction, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return transaction{}, errTransactionCookieMalformed
	}
	aead, err := newAEAD(key)
	if err != nil {
		return transaction{}, err
	}
	if len(ciphertext) <= aead.NonceSize() {
		return transaction{}, errTransactionCookieMalformed
	}
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return transaction{}, errTransactionCookieInvalid
	}
	var value transaction
	if err := json.Unmarshal(plaintext, &value); err != nil {
		return transaction{}, errTransactionCookieMalformed
	}
	if value.State == "" || value.Nonce == "" || value.CodeVerifier == "" || value.RedirectURL == "" {
		return transaction{}, errTransactionCookieIncomplete
	}
	if value.ExpiresAt.IsZero() || !now.Before(value.ExpiresAt) {
		return transaction{}, errTransactionCookieExpired
	}
	return value, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create transaction cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create transaction AEAD: %w", err)
	}
	return aead, nil
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func codeChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func transactionCookie(config CookieConfig, value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     config.Name,
		Value:    value,
		Path:     config.Path,
		Domain:   config.Domain,
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   config.Secure,
		SameSite: config.SameSite,
	}
}
