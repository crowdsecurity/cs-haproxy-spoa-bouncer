package captcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CaptchaToken represents the payload stored in a signed captcha cookie
type CaptchaToken struct {
	UUID string `json:"uuid"` // UUID for traceability and debugging
	St   string `json:"st"`   // status: "pending", "passed", "failed", etc.
	Iat  int64  `json:"iat"`  // issued at (unix seconds)
	Exp  int64  `json:"exp"`  // expires at (unix seconds)
}

const (
	// DefaultPendingTTL is the default TTL for pending captcha tokens (30 minutes)
	DefaultPendingTTL = 30 * time.Minute
	// DefaultPassedTTL is the default TTL for passed captcha tokens (24 hours)
	DefaultPassedTTL = 24 * time.Hour
)

// SignCaptchaToken signs a CaptchaToken and returns a signed string in the format "payload.sig"
// The payload is base64url-encoded JSON, and the signature is HMAC-SHA256 of the payload
func SignCaptchaToken(tok CaptchaToken, secret []byte) (string, error) {
	// Serialize token to JSON
	jsonData, err := json.Marshal(tok)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	// Base64url-encode the payload
	payload := base64.RawURLEncoding.EncodeToString(jsonData)

	// Compute HMAC-SHA256 signature
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)

	// Base64url-encode the signature
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	// Return format: payload.sig
	return payload + "." + sigB64, nil
}

// ParseAndVerifyCaptchaToken parses and verifies a signed captcha token string
// Returns the token if valid, or an error if invalid, expired, or tampered with
func ParseAndVerifyCaptchaToken(raw string, secret []byte) (*CaptchaToken, error) {
	if raw == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Split on "." to get payload and signature
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format: expected payload.sig")
	}

	payload := parts[0]
	sigB64 := parts[1]

	// Decode the signature
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Recompute HMAC
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	expectedSig := mac.Sum(nil)

	// Constant-time comparison
	if !hmac.Equal(sig, expectedSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode the payload
	jsonData, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Unmarshal JSON into token
	var tok CaptchaToken
	if err := json.Unmarshal(jsonData, &tok); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	// Check expiration
	now := time.Now().Unix()
	if now > tok.Exp {
		return nil, fmt.Errorf("token expired: exp=%d, now=%d", tok.Exp, now)
	}

	return &tok, nil
}

// IsPassed checks if the token indicates the captcha was passed (not expired and status is valid)
func (t *CaptchaToken) IsPassed() bool {
	return time.Now().Unix() <= t.Exp && t.St == Valid
}

// IsPending checks if the token indicates the captcha is pending (not expired and status is pending)
func (t *CaptchaToken) IsPending() bool {
	return time.Now().Unix() <= t.Exp && t.St == Pending
}

// GenerateCaptchaCookie generates an HTTP cookie from a captcha token (stateless)
// The cookie is a session cookie (no Expires/MaxAge) with the signed token as the value
func GenerateCaptchaCookie(tok CaptchaToken, secret string, name string, httpOnly bool, secure bool) (*http.Cookie, error) {
	// Sign the token
	signedToken, err := SignCaptchaToken(tok, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign captcha token: %w", err)
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    signedToken,
		MaxAge:   0, // Session cookie (no Expires/MaxAge)
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}

	// Base64url-encode the cookie value
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))
	if len(cookie.String()) > 4096 {
		return nil, fmt.Errorf("cookie value too long")
	}

	return cookie, nil
}

// ValidateCaptchaCookie validates a base64-encoded captcha cookie value and returns the parsed token
// Returns the token if valid, or an error if invalid, expired, or tampered with
func ValidateCaptchaCookie(b64Value string, secret string) (*CaptchaToken, error) {
	// Decode base64-encoded cookie value
	value, err := base64.URLEncoding.DecodeString(b64Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cookie value: %w", err)
	}

	// Parse and verify the signed token
	tok, err := ParseAndVerifyCaptchaToken(string(value), []byte(secret))
	if err != nil {
		return nil, err
	}

	return tok, nil
}
